import conexion from "../bd.js";  // Importa la conexión a la base de datos
import bcrypt from "bcrypt";      // Importa bcrypt para comparar hashes

export default async function requireAuth(req, res, next) {
  try {
    // 🔹 Obtener todas las cookies enviadas por el cliente
    const cookies = req.cookies;

    // 🔹 Si no hay cookies, acceso denegado
    if (!cookies || Object.keys(cookies).length === 0) {
      return res.status(401).json({ mensaje: "No hay cookies, acceso denegado." });
    }

    let usuarioId = null; // 🔹 Aquí guardaremos el ID del usuario si la cookie es válida

    // 🔹 Iterar sobre las cookies para encontrar la que corresponde al usuario
    for (const nombreCookie in cookies) {
      // 🔹 Comparar el nombre de la cookie con "id" hasheado
      const esMatch = await bcrypt.compare("id", nombreCookie);

      if (esMatch) {
        // 🔹 Si coincide, obtener todos los IDs de usuarios de la DB
        const [usuarios] = await conexion.query("SELECT id FROM usuarios");

        // 🔹 Comparar el valor de la cookie con los IDs hasheados de los usuarios
        for (const u of usuarios) {
          const idMatch = await bcrypt.compare(u.id.toString(), cookies[nombreCookie]);
          if (idMatch) {
            usuarioId = u.id; // Guardar el ID del usuario válido
            break;            // Salir del loop si encontramos coincidencia
          }
        }
        break; // Salir del loop de cookies
      }
    }

    // 🔹 Si no se encuentra un usuario válido, denegar acceso
    if (!usuarioId) {
      return res.status(401).json({ mensaje: "Cookie inválida o usuario no encontrado." });
    }

    // 🔹 Guardar el ID del usuario en la request para usarlo en los siguientes middlewares o rutas
    req.usuarioId = usuarioId;

    // 🔹 Continuar con la siguiente función o endpoint
    next();

  } catch (error) {
    // 🔹 Captura de errores inesperados
    console.error('Error en requireAuth:', error);
    return res.status(500).json({ mensaje: 'Error interno del servidor.' });
  }
}
