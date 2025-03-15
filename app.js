const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const path = require('path');
require('dotenv').config();

const app = express();

// Middleware
app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

// MongoDB connection with better error handling
console.log('Intentando conectar a MongoDB:', process.env.MONGODB_URI);
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('Conexión exitosa a MongoDB Atlas');
}).catch(err => {
    console.error('Error al conectar a MongoDB:', err);
});

// Mongoose connection events
mongoose.connection.on('error', err => {
    console.error('Error de MongoDB:', err);
});

mongoose.connection.on('disconnected', () => {
    console.log('Desconectado de MongoDB');
});

mongoose.connection.on('connected', () => {
    console.log('Conectado a MongoDB');
});

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    points: { type: Number, default: 0 },
    cards: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Card' }],
    isAdmin: { type: Boolean, default: false },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Card Schema
const cardSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String, required: true },
    imageUrl: { type: String, required: true },
    type: { type: String, required: true },
    rarity: { type: String, required: true },
    points: { type: Number, required: true }
});

const Card = mongoose.model('Card', cardSchema);

// Transaction Schema
const transactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, required: true }, // 'earn' or 'redeem'
    points: { type: Number, required: true },
    details: { type: String, required: true },
    date: { type: Date, default: Date.now }
});

const Transaction = mongoose.model('Transaction', transactionSchema);

// Reward Schema
const Reward = require('./models/Reward');

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware para verificar el token JWT
function authenticateToken(req, res, next) {
    const token = req.cookies.token;
    
    if (!token) {
        return res.redirect('/login');
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.redirect('/login');
        }
        req.user = user;
        next();
    });
}

// Middleware para verificar rol de admin
function isAdmin(req, res, next) {
    if (!req.user) {
        return res.redirect('/login');
    }

    User.findById(req.user.userId)
        .then(user => {
            if (!user || !user.isAdmin) {
                return res.redirect('/');
            }
            next();
        })
        .catch(err => {
            console.error('Error al verificar admin:', err);
            res.redirect('/login');
        });
}

// Routes
app.get('/', async (req, res) => {
    try {
        const token = req.cookies.token;
        if (token) {
            const decoded = jwt.verify(token, JWT_SECRET);
            const user = await User.findById(decoded.userId);
            if (user) {
                return res.render('index', { 
                    user,
                    isAuthenticated: true,
                    isAdmin: user.isAdmin
                });
            }
        }
        res.render('index', { 
            isAuthenticated: false,
            isAdmin: false
        });
    } catch (error) {
        console.error('Error in home route:', error);
        res.render('index', { 
            isAuthenticated: false,
            isAdmin: false
        });
    }
});

app.get('/register', (req, res) => {
    res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
    try {
        console.log('Intentando registrar usuario:', req.body.email);
        const { username, email, password, confirmPassword } = req.body;

        // Validate password match
        if (password !== confirmPassword) {
            return res.render('register', { 
                error: 'Las contraseñas no coinciden',
                username,
                email
            });
        }

        // Verificar si el usuario ya existe
        const existingUser = await User.findOne({ 
            $or: [{ email }, { username }] 
        });

        if (existingUser) {
            return res.render('register', { 
                error: 'El usuario o correo electrónico ya existe',
                username,
                email
            });
        }

        // Hash de la contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        // Crear nuevo usuario
        const user = new User({
            username,
            email,
            password: hashedPassword,
            points: 1000, // Puntos iniciales
            isAdmin: false
        });

        await user.save();
        console.log('Usuario registrado exitosamente:', email);

        // Create initial transaction for welcome points
        const transaction = new Transaction({
            userId: user._id,
            type: 'earn',
            points: 1000,
            details: 'Puntos de bienvenida'
        });
        await transaction.save();

        // Create JWT token
        const token = jwt.sign(
            { userId: user._id },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Set cookie and redirect
        res.cookie('token', token, { httpOnly: true });
        res.redirect('/dashboard');

    } catch (error) {
        console.error('Error en registro:', error);
        res.render('register', { 
            error: 'Error al registrar el usuario',
            username: req.body.username,
            email: req.body.email
        });
    }
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.render('login', { 
                error: 'Usuario o contraseña incorrectos',
                email
            });
        }

        // Check if user is active
        if (!user.isActive) {
            return res.render('login', { 
                error: 'Tu cuenta está desactivada. Contacta al administrador.',
                email
            });
        }

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.render('login', { 
                error: 'Usuario o contraseña incorrectos',
                email
            });
        }

        // Create JWT token with user role
        const token = jwt.sign(
            { 
                userId: user._id,
                isAdmin: user.isAdmin 
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Set cookie and redirect based on role
        res.cookie('token', token, { httpOnly: true });
        if (user.isAdmin) {
            res.redirect('/admin');
        } else {
            res.redirect('/dashboard');
        }

    } catch (error) {
        console.error('Error en login:', error);
        res.render('login', { 
            error: 'Error al iniciar sesión',
            email: req.body.email
        });
    }
});

app.get('/dashboard', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        const rewards = await Reward.find({ isAvailable: true });

        res.render('dashboard', {
            user: {
                name: user.username,
                points: user.points || 0
            },
            rewards: rewards.map(reward => ({
                _id: reward._id,
                name: reward.name,
                description: reward.description,
                imageUrl: reward.imageUrl,
                pointsRequired: reward.pointsRequired,
                stock: reward.stock
            }))
        });
    } catch (error) {
        console.error('Error al cargar el dashboard:', error);
        res.status(500).send('Error interno del servidor');
    }
});

app.post('/claim-reward', authenticateToken, async (req, res) => {
    try {
        const { rewardId } = req.body;
        const user = await User.findById(req.user.userId);
        const reward = await Reward.findById(rewardId);

        if (!reward) {
            return res.status(404).json({ error: 'Recompensa no encontrada' });
        }

        if (reward.stock <= 0) {
            return res.status(400).json({ error: 'No hay stock disponible' });
        }

        if (user.points < reward.pointsRequired) {
            return res.status(400).json({ error: 'No tienes suficientes puntos' });
        }

        // Actualizar puntos del usuario y stock de la recompensa
        user.points -= reward.pointsRequired;
        reward.stock -= 1;

        await user.save();
        await reward.save();

        res.json({ success: true });
    } catch (error) {
        console.error('Error al canjear recompensa:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.get('/cards', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        const cards = await Card.find();

        res.render('cards', {
            user: {
                name: user.username,
                pokePoints: user.points
            },
            cards
        });
    } catch (error) {
        console.error('Cards page error:', error);
        res.redirect('/dashboard');
    }
});

app.post('/redeem', authenticateToken, async (req, res) => {
    try {
        const { cardId } = req.body;
        const user = await User.findById(req.user.userId);
        const card = await Card.findById(cardId);

        if (!card) {
            return res.status(404).json({ success: false, error: 'Carta no encontrada' });
        }

        if (user.points < card.points) {
            return res.status(400).json({ success: false, error: 'Puntos insuficientes' });
        }

        // Update user points and add card to collection
        user.points -= card.points;
        user.cards.push(card._id);
        await user.save();

        // Create transaction record
        const transaction = new Transaction({
            userId: user._id,
            type: 'redeem',
            points: -card.points,
            details: `Canjeado: ${card.name}`
        });
        await transaction.save();

        res.redirect('/dashboard');
    } catch (error) {
        console.error('Redeem error:', error);
        res.status(500).json({ success: false, error: 'Error al canjear la carta' });
    }
});

// Logout route
app.get('/logout', (req, res) => {
    // Clear the JWT token cookie
    res.clearCookie('token');
    // Redirect to home page
    res.redirect('/');
});

// Admin routes
app.get('/admin', authenticateToken, isAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user || !user.isAdmin) {
            return res.redirect('/');
        }

        const users = await User.find();
        const cards = await Card.find();
        const rewards = await Reward.find();
        const transactions = await Transaction.find().sort({ date: -1 }).limit(10);

        res.render('admin', {
            user,
            users,
            cards,
            rewards,
            transactions,
            isAuthenticated: true,
            isAdmin: true
        });
    } catch (error) {
        console.error('Error en el panel de administración:', error);
        res.status(500).send('Error interno del servidor');
    }
});

app.post('/admin/add-points', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { userId, points, reason } = req.body;
        const user = await User.findById(userId);
        
        if (!user) {
            return res.status(404).json({ success: false, error: 'Usuario no encontrado' });
        }

        // Update user points
        user.points += parseInt(points);
        await user.save();

        // Create transaction record
        const transaction = new Transaction({
            userId: user._id,
            type: points >= 0 ? 'earn' : 'redeem',
            points: parseInt(points),
            details: reason || 'Ajuste de puntos por administrador'
        });
        await transaction.save();

        res.json({ success: true });
    } catch (error) {
        console.error('Error adding points:', error);
        res.status(500).json({ success: false, error: 'Error al ajustar puntos' });
    }
});

app.post('/admin/toggle-user', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { userId } = req.body;
        const user = await User.findById(userId);
        
        if (!user) {
            return res.status(404).json({ success: false, error: 'Usuario no encontrado' });
        }

        user.isActive = !user.isActive;
        await user.save();

        res.json({ success: true });
    } catch (error) {
        console.error('Error toggling user:', error);
        res.status(500).json({ success: false, error: 'Error al cambiar estado del usuario' });
    }
});

app.post('/admin/add-card', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { name, description, imageUrl, type, rarity, points } = req.body;
        
        const card = new Card({
            name,
            description,
            imageUrl,
            type,
            rarity,
            points: parseInt(points)
        });
        
        await card.save();
        res.json({ success: true });
    } catch (error) {
        console.error('Error adding card:', error);
        res.status(500).json({ success: false, error: 'Error al agregar carta' });
    }
});

app.delete('/admin/delete-card', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { cardId } = req.body;
        await Card.findByIdAndDelete(cardId);
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting card:', error);
        res.status(500).json({ success: false, error: 'Error al eliminar carta' });
    }
});

app.post('/admin/add-reward', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { name, description, pointsRequired, stock, imageUrl, isAvailable } = req.body;
        
        const reward = new Reward({
            name,
            description,
            pointsRequired,
            stock,
            imageUrl,
            isAvailable
        });

        await reward.save();
        res.json({ success: true, reward });
    } catch (error) {
        console.error('Error adding reward:', error);
        res.status(500).json({ success: false, error: 'Error al agregar la recompensa' });
    }
});

app.put('/admin/update-reward/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { name, description, pointsRequired, stock, imageUrl, isAvailable } = req.body;
        
        const reward = await Reward.findByIdAndUpdate(
            req.params.id,
            {
                name,
                description,
                pointsRequired,
                stock,
                imageUrl,
                isAvailable
            },
            { new: true }
        );

        if (!reward) {
            return res.status(404).json({ success: false, error: 'Recompensa no encontrada' });
        }

        res.json({ success: true, reward });
    } catch (error) {
        console.error('Error updating reward:', error);
        res.status(500).json({ success: false, error: 'Error al actualizar la recompensa' });
    }
});

app.delete('/admin/delete-reward/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const reward = await Reward.findByIdAndDelete(req.params.id);
        
        if (!reward) {
            return res.status(404).json({ success: false, error: 'Recompensa no encontrada' });
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting reward:', error);
        res.status(500).json({ success: false, error: 'Error al eliminar la recompensa' });
    }
});

// API de Recompensas
app.get('/api/rewards/:id', authenticateToken, async (req, res) => {
    try {
        const reward = await Reward.findById(req.params.id);
        if (!reward) {
            return res.status(404).json({ error: 'Recompensa no encontrada' });
        }
        res.json(reward);
    } catch (error) {
        console.error('Error al obtener recompensa:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.post('/api/rewards', authenticateToken, async (req, res) => {
    try {
        const { name, description, imageUrl, pointsRequired, stock, active } = req.body;
        const reward = new Reward({
            name,
            description,
            imageUrl,
            pointsRequired,
            stock,
            active
        });
        await reward.save();
        res.status(201).json(reward);
    } catch (error) {
        console.error('Error al crear recompensa:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.put('/api/rewards/:id', authenticateToken, async (req, res) => {
    try {
        const { name, description, imageUrl, pointsRequired, stock, active } = req.body;
        const reward = await Reward.findByIdAndUpdate(
            req.params.id,
            {
                name,
                description,
                imageUrl,
                pointsRequired,
                stock,
                active
            },
            { new: true }
        );
        if (!reward) {
            return res.status(404).json({ error: 'Recompensa no encontrada' });
        }
        res.json(reward);
    } catch (error) {
        console.error('Error al actualizar recompensa:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.delete('/api/rewards/:id', authenticateToken, async (req, res) => {
    try {
        const reward = await Reward.findByIdAndDelete(req.params.id);
        if (!reward) {
            return res.status(404).json({ error: 'Recompensa no encontrada' });
        }
        res.status(204).send();
    } catch (error) {
        console.error('Error al eliminar recompensa:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Start server
const PORT = process.env.PORT || 3006;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor corriendo en puerto ${PORT}`);
});
