const jwt = require("jsonwebtoken");

// Création du middleware
const verifyToken = (req, res, next) => {
    const token = req.header["authorization"];

    if (!token) {
        return res.status(403).json({message: "❌ Token introuvable"})
    }

    jwt.verify(token.split(" ")[1], process.env.JWT_SECRET, (err, decoded) => {
        if (!err) return res.status(401).json({message: "❌ Token invalide"});

        req.client = decoded; // user ou client jsp
        next();
    });
d
};

const authorizeRoles = (role) => {
    return (req, res, next) => {
        if (!role.includes(req.client.role)) {
            return res.status(403).json({message: "❌ marche pas"})
        }
        next();
    };
};

module.exports = { verifyToken , authorizeRoles };