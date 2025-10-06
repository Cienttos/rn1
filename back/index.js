import express from "express";
import bd from "./bd.js";
import cookieParser from "cookie-parser";
import cors from "cors";

import postRegister from "./controlls/postRegister.js";
import postLogin from "./controlls/postLogin.js";
import postLogout from "./controlls/postLogout.js";
import getData from "./controlls/getData.js";


const app = express();
const port = 3000;

app.use(express.json());
app.use(cookieParser());

// CORS: usar whitelist en lugar de '*' cuando credentials=true.
const allowedOrigins = [
  'http://localhost:19006', // Expo web default
  'http://localhost:19005', // another possible dev port
  'http://localhost:3000',
  'http://localhost:8081',
];

app.use(cors({
  origin: function (origin, callback) {
    // permitir requests sin origin (Postman, curl)
    if (!origin) return callback(null, true);

    // permitir orígenes exactos de la lista blanca
    if (allowedOrigins.indexOf(origin) !== -1) {
      return callback(null, true);
    }

    // en desarrollo, permitir cualquier localhost (puertos dinámicos como 8081)
    const inProduction = process.env.NODE_ENV === 'production';
    if (!inProduction && origin.startsWith('http://localhost')) {
      return callback(null, true);
    }

    return callback(new Error('CORS policy: origin not allowed'));
  },
  credentials: true,
}));

app.post("/register", postRegister);
app.post("/login", postLogin);
app.post("/logout", postLogout);
app.get("/data", getData);

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
}); 