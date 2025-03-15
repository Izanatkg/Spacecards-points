# PokéPuntos - Sistema de Recompensas Pokémon

Una aplicación web que permite a los usuarios ganar y canjear PokéPuntos por cartas Pokémon. Construida con Node.js, Express, MongoDB y EJS.

## Características

- Sistema de registro y autenticación de usuarios
- Dashboard personalizado para cada usuario
- Sistema de puntos basado en compras
- Catálogo de cartas Pokémon para canjear
- Panel de administración
- Diseño responsivo y temático de Pokémon

## Requisitos

- Node.js (v14 o superior)
- MongoDB
- npm o yarn

## Configuración

1. Clona el repositorio:
```bash
git clone <url-del-repositorio>
cd pokemon-points-app
```

2. Instala las dependencias:
```bash
npm install
```

3. Crea un archivo `.env` en la raíz del proyecto:
```env
MONGODB_URI=mongodb://localhost:27017/pokemon-points
JWT_SECRET=tu-secreto-aqui
MAIL_USER=tu-email@gmail.com
MAIL_PASS=tu-contraseña-email
```

4. Inicia la aplicación:
```bash
npm start
```

## Estructura del Proyecto

```
pokemon-points-app/
├── app.js              # Archivo principal de la aplicación
├── public/            # Archivos estáticos
│   ├── css/          # Hojas de estilo
│   ├── js/           # Scripts del cliente
│   └── img/          # Imágenes
├── views/            # Plantillas EJS
├── models/           # Modelos de MongoDB
└── routes/           # Rutas de la aplicación
```

## Uso

1. Regístrate como nuevo usuario
2. Realiza compras para ganar PokéPuntos
3. Visita la sección de cartas para canjear tus puntos
4. Colecciona cartas Pokémon únicas

## Contribuir

1. Haz fork del repositorio
2. Crea una rama para tu característica (`git checkout -b feature/nueva-caracteristica`)
3. Haz commit de tus cambios (`git commit -am 'Agrega nueva característica'`)
4. Push a la rama (`git push origin feature/nueva-caracteristica`)
5. Crea un Pull Request

## Licencia

Este proyecto está bajo la Licencia MIT.
