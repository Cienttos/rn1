export default function postLogout(req, res) {
  try {
    // 🔹 Obtener todas las cookies enviadas por el cliente
    const cookies = req.cookies;

    // 🔹 Si no hay cookies, significa que no hay sesión activa
    if (!cookies || Object.keys(cookies).length === 0) {
      return res.status(400).json({ mensaje: "No hay sesión activa." });
    }

    // 🔹 Iterar sobre todas las cookies y eliminarlas
    for (const nombreCookie in cookies) {
      if (nombreCookie) {
        // 🔹 Configuración de seguridad según el entorno
        const inProduction = process.env.NODE_ENV === 'production';
        
        // 🔹 Limpiar la cookie (borrar del navegador)
        res.clearCookie(nombreCookie, {
          httpOnly: true,               // Solo accesible por el servidor
          secure: inProduction,          // Solo HTTPS si estamos en producción
          sameSite: inProduction ? 'strict' : 'lax', // Política SameSite
        });
      }
    }

    // 🔹 Devolver mensaje de éxito
    return res.status(200).json({ mensaje: "Sesión cerrada correctamente." });

  } catch (error) {
    // 🔹 Captura cualquier error inesperado y devuelve 500
    console.error("Error en postLogout:", error);
    return res.status(500).json({ mensaje: "Error al cerrar la sesión." });
  }
}
