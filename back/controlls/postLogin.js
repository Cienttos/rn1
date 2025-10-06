import conexion from "../bd.js";  // Importa la conexión a la base de datos
import bcrypt from "bcrypt";      // Importa bcrypt para hashear y comparar contraseñas

export default async function postLogin(req, res) {
    try {
        // 🔹 Obtener email y password del cuerpo de la petición
        const { email, password } = req.body;

        // 🔹 Validar que se envíen los campos obligatorios
        if (!email || !password)
            return res.status(400).json({ mensaje: "Faltan datos obligatorios." });

        // 🔹 Buscar al usuario en la base de datos por su email
        const [usuarios] = await conexion.query(
            "SELECT * FROM usuarios WHERE email = ?",
            [email.trim().toLowerCase()]
        );

        // 🔹 Si no se encuentra el usuario, devolver error
        if (usuarios.length === 0)
            return res.status(401).json({ mensaje: "Usuario o contraseña incorrectos." });

        const usuario = usuarios[0]; // Tomar el primer (y único) usuario encontrado

        // 🔹 Comparar la contraseña ingresada con la almacenada (hasheada)
        const esValida = await bcrypt.compare(password, usuario.password);
        if (!esValida)
            return res.status(401).json({ mensaje: "Usuario o contraseña incorrectos." });

        // 🔹 Hashear el ID del usuario para guardarlo en la cookie
        const hashedId = await bcrypt.hash(usuario.id.toString(), 10);

        // 🔹 Hashear también el nombre de la cookie ("id")
        const hashedCookieName = await bcrypt.hash("id", 10);

        // 🔹 Configuración de seguridad de la cookie según el entorno
        const inProduction = process.env.NODE_ENV === 'production';
        res.cookie(hashedCookieName, hashedId, {
            httpOnly: true,            // La cookie no es accesible desde JavaScript
            secure: inProduction,       // Solo en HTTPS si está en producción
            sameSite: inProduction ? 'strict' : 'lax', // Política de SameSite
            maxAge: 24 * 60 * 60 * 1000 // 1 día de duración
        });

        // 🔹 Devolver mensaje de éxito
        return res.status(200).json({ mensaje: "Inicio de sesión exitoso." });

    } catch (error) {
        // 🔹 Captura cualquier error inesperado y devuelve 500
        console.error("Error en postLogin:", error);
        return res.status(500).json({ mensaje: "Error interno del servidor." });
    }
}
