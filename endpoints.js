const express = require("express");
const db = require("./db");
const bcrypt = require("bcrypt");
const router = express.Router();
const jwt = require("jsonwebtoken");
const { sign } = require("jsonwebtoken");
const {compare} = require("bcrypt");
const { verifyToken, authorizeRoles } = require('./middleware')

/**
 * ➤ ROUTE : Inscription d'un nouveau client
 * ➤ URL : POST /api/clients/register
 * ➤ Body attendu (JSON) :
 *   {
 *     "prenom": "Tim",
 *     "nom": "Fromentin",
 *     "email": "tim.fromentin@example.com",
 *     "mot_de_passe": "caravane",
 *     "adresse": "dans la caravane",
 *     "telephone": "0612345678",
 *     "role": "client",
 *     "date_inscription": "2025-02-06"
 *   }
 */
router.post("/clients/register", (req, res) => {
    const  { prenom, nom, email, mot_de_passe, adresse, telephone, role, date_inscription } = req.body;

    // Vérifier si l'email existe déjà
    db.query("SELECT * FROM utilisateurs WHERE email = ?", [email], (err, result) => {
        if (err) {
            console.log(err)
            return res.status(500).json({message: "Erreur serveur"});
        }

        if (result.length > 0) {
            return res.status(400).json({ message: "Cet email est déjà utilisé" });
        }

        // Hachage du mot de passe avant insertion
        bcrypt.hash(mot_de_passe, 10, (err, hash) => {
            if (err) return res.status(500).json({ message: "Erreur lors du hachage du mot de passe" });

            // Insérer le nouveau client
            db.query(
                "INSERT INTO utilisateurs (prenom, nom, email, mot_de_passe, adresse, telephone, role, date_inscription) VALUES (?, ?, ?, ?, ?, ?, ? ,?)",
                [prenom, nom, email, hash, adresse, telephone, role, date_inscription],
                (err, result) => {
                    if (err) {
                        console.log(err)
                        return res.status(500).json({ message: "Erreur lors de l'inscription" });
                    }

                    res.status(201).json({
                        message: "Inscription réussie",
                        client_id: result.insertId
                    });
                }
            );
        });
    });
});

/**
 * ➤ ROUTE : Connexion d'un client (Génération de JWT)
 * ➤ URL : POST /api/clients/login
 * {
 *     "email": "jean.dupont@email.com",
 *     "mot_de_passe": "hashpassword1"
 * }
 */
/**
 * ➤ ROUTE : Connexion d'un client (Génération de JWT)
 * ➤ URL : POST /api/clients/login
 * {
 *     "email": "jean.dupont@email.com",
 *     "mot_de_passe": "hashpassword1"
 * }
 */
router.post("/clients/login", (req, res) => {
    const { email, mot_de_passe } = req.body;

    // Récupérer les infos de la bdd
    db.query("SELECT * FROM utilisateurs WHERE email = ?", [email], (err, result) => {
        console.log(result)
        if (err) return res.status(500).json({message: "❌ Erreur de la bdd"});
        if (result.length === 0) return res.status(404).json({ message: "❌ Utilisateur non trouvé" });

        const client = result[0];

        bcrypt.compare(mot_de_passe, client.mot_de_passe, (err, isMatch) => {
            if (err) return res.status(500).json({message: "❌ Erreur serveur"});
            if (!isMatch) return res.status(401).json({message:"❌ Identifiants incorrects"});

            // Encodage du JWT via la variable d'environnement JWT_SECRET
            const jwtToken = jwt.sign(
                { email, role: client.role },
                process.env.JWT_SECRET,
                {expiresIn: process.env.JWT_EXPIRES_IN}
            );

            // Stockage du JWT dans un cookie HttpOnly
            //res.cookie("jwtToken", jwtToken, { httpOnly: true, secure: true });
            //res.json(jwtToken);

            res.json({
                jwtToken,
                client : {
                    id: client.id,
                    nom: client.nom,
                    prenom: client.prenom,
                    email: client.email,
                }
            })
        })
    })
})

/**
 * ➤ ROUTE : Déconnexion d'un client (Génération de JWT)
 * ➤ URL : POST /api/clients/register
 */
router.get("/logout", (req, res) => {
    res.clearCookie("jwtToken");
    res.redirect('/');
});

/**
 * ➤ ROUTE : Récupérer tous les produits
 */
router.get("/produits", (req, res) => {
    db.query("SELECT * FROM produits",
        (err, result) => {
        if (err) return res.status(500).json({ message: "❌ Erreur serveur" });
        res.json(result);
    });
});

/**

 * ➤ ROUTE : BEST SELLERS - Page d'accueil
 */
router.get("/home-best-sellers", (req, res) => {
    db.query("SELECT * FROM produits JOIN variante_poids ON produits.id = variante_poids.id_produit LIMIT 0,6", (err, result) => {
        if (err) return res.status(500).json({ message: "❌ Erreur serveur" });
        res.json(result);
    });
});

/**
 * ➤ ROUTE : Récupérer variantes de poids d'un produit
 */
router.get("/variantes/poids/:id", (req, res) => {
    const id = parseInt(req.params.id);

    db.query("SELECT poids, prix FROM variante_poids WHERE id_produit = ?", [id], (err, result) => {
        if (err) return res.status(500).json({message: "Erreur serveur"});
        console.log(res.json(result));
    })
})

/**
 * ➤ ROUTE : Récupérer un produit par son ID
 * ➤ URL : GET /api/produits/:id
 * ➤ Exemple d'utilisation : GET /api/produits/1
 */
router.get("/produits/:id", (req , res) => {
    const id = parseInt(req.params.id);

    db.query("SELECT * FROM produits WHERE id = ?", [id], (err, result) => {
        if (err) return res.status(500).json({message:"❌ Erreur serveur"});
        res.json(result[0]);
    });
});


/**
 * ➤ ROUTE : Ajouter un produit au panier
 * ➤ URL : POST /api/panier/ajouter
 * ➤ Body attendu (JSON) :
 * {
 *     "client_id": 1,
 *     "produit_id": 2,
 *     "variante_poids": "250",
 *     "quantite": 1,
 *     "prix": 12.50
 * }
 */
router.post("/panier/ajouter", (req, res) => {
    const { client_id, produit_id, variante_poids, quantite, prix } = req.body;

    // Si l'utilisateur est connecté, sauvegarde dans la base de données
    if (client_id) {
        // Vérifier si le produit est déjà dans le panier
        db.query(
            "SELECT * FROM panier WHERE client_id = ? AND produit_id = ? AND variante_poids = ?",
            [client_id, produit_id, variante_poids],
            (err, result) => {
                if (err) return res.status(500).json({ message: "❌ Erreur serveur" });

                if (result.length > 0) {
                    // Le produit existe déjà, mettre à jour la quantité
                    const nouvelleQuantite = result[0].quantite + quantite;

                    db.query(
                        "UPDATE panier SET quantite = ? WHERE id = ?",
                        [nouvelleQuantite, result[0].id],
                        (err, updateResult) => {
                            if (err) return res.status(500).json({ message: "❌ Erreur de mise à jour" });

                            return res.status(200).json({
                                message: "✅ Quantité mise à jour dans le panier",
                                panier_id: result[0].id
                            });
                        }
                    );
                } else {
                    // Le produit n'existe pas, l'ajouter au panier
                    db.query(
                        "INSERT INTO panier (client_id, produit_id, variante_poids, quantite, prix) VALUES (?, ?, ?, ?, ?)",
                        [client_id, produit_id, variante_poids, quantite, prix],
                        (err, insertResult) => {
                            if (err) return res.status(500).json({ message: "❌ Erreur d'ajout au panier" });

                            return res.status(201).json({
                                message: "✅ Produit ajouté au panier",
                                panier_id: insertResult.insertId
                            });
                        }
                    );
                }
            }
        );
    } else {
        // Pour les utilisateurs non connectés, on renvoie les données pour stockage local
        return res.status(200).json({
            message: "✅ Produit ajouté au panier (session locale)",
            produit: { produit_id, variante_poids, quantite, prix }
        });
    }
});

/**
 * ➤ ROUTE : Récupérer le panier d'un client
 * ➤ URL : GET /api/panier/:client_id
 */
router.get("/panier/:client_id", (req, res) => {
    const client_id = req.params.client_id;

    db.query(
        `SELECT p.id, p.produit_id, p.variante_poids, p.quantite, p.prix, 
                prod.nom, prod.image 
         FROM panier p
         JOIN produits prod ON p.produit_id = prod.id
         WHERE p.client_id = ?`,
        [client_id],
        (err, result) => {
            if (err) return res.status(500).json({ message: "❌ Erreur serveur" });

            const total = result.reduce((sum, item) => sum + (item.prix * item.quantite), 0);

            return res.status(200).json({
                items: result,
                total: total,
                count: result.length
            });
        }
    );
});

/**
 * ➤ ROUTE : Supprimer un article du panier
 * ➤ URL : DELETE /api/panier/:id
 */
router.delete("/panier/:id", (req, res) => {
    const produitId = req.params.id;
    const clientId = req.query.client_id; // Récupérer client_id depuis les paramètres de l'URL

    if (!clientId) {
        return res.status(400).json({ message: "❌ client_id est requis" });
    }

    db.query("DELETE FROM panier WHERE produit_id = ? AND client_id = ?", [produitId, clientId], (err, result) => {
        if (err) {
            console.error("Erreur SQL :", err);
            return res.status(500).json({ message: "❌ Erreur serveur" });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "⚠️ Article introuvable dans le panier" });
        }

        return res.status(200).json({ message: "✅ Article supprimé du panier" });
    });
});

/**
 * ➤ ROUTE : Mettre à jour la quantité d'un article
 * ➤ URL : PUT /api/panier/:id
 * ➤ Body attendu (JSON) :
 * {
 *     "quantite": 3
 * }
 */
router.put("/panier/:id", (req, res) => {
    const produitId = req.params.id;
    const { quantite, client_id } = req.body; // Récupérer les données depuis le body

    if (!quantite || !client_id) {
        return res.status(400).json({ message: "❌ Quantité et client_id sont requis" });
    }

    console.log(`🔄 Mise à jour du produit ${produitId} pour le client ${client_id} avec quantité ${quantite}`);

    db.query(
        "UPDATE panier SET quantite = ? WHERE produit_id = ? AND client_id = ?",
        [quantite, produitId, client_id],
        (err, result) => {
            if (err) {
                console.error("❌ Erreur SQL :", err);
                return res.status(500).json({ message: "❌ Erreur serveur" });
            }

            if (result.affectedRows === 0) {
                return res.status(404).json({ message: "⚠️ Article introuvable dans le panier" });
            }

            return res.status(200).json({ message: "✅ Quantité mise à jour avec succès" });
        }
    );
});

/**
 * ➤ ROUTE : Passer une commande
 * fetch("/order", {
 *     method: "POST",
 *     headers: { "Content-Type": "application/json" },
 *     body: JSON.stringify({
 *         client_id: 1,
 *         adresse_livraison: "123 Rue des Lilas, Paris",
 *         transporteur: "Colissimo",
 *         methode_paiement: "Carte bancaire"
 *     })
 * })
 * .then(res => res.json())
 * .then(data => alert(data.message))
 * .catch(err => console.error("Erreur :", err));
 */
router.post("/order", (req, res) => {
    const { client_id, adresse_livraison, transporteur, methode_paiement } = req.body;

    // Vérifier si le panier du client contient des produits
    db.query(
        "SELECT produit_id, quantite, prix FROM panier WHERE client_id = ?",
        [client_id],
        (err, panier) => {
            if (err) return res.status(500).json({ message: "❌ Erreur serveur" });
            if (panier.length === 0) return res.status(400).json({ message: "❌ Le panier est vide." });

            // Calculer le total de la commande
            let total = panier.reduce((acc, item) => acc + item.prix * item.quantite, 0);

            // Insérer la commande
            db.query(
                "INSERT INTO commandes (client_id, total, statut, date_commande) VALUES (?, ?, ?, NOW())",
                [client_id, total, "En attente"],
                (err, resultCommande) => {
                    if (err) return res.status(500).json({ message: "❌ Erreur lors de la création de la commande" });

                    const commande_id = resultCommande.insertId;

                    // Insérer les produits dans 'details_commandes'
                    const values = panier.map(item => [commande_id, item.produit_id, item.quantite]);

                    db.query(
                        "INSERT INTO details_commandes (commande_id, produit_id, quantite) VALUES ?",
                        [values],
                        (err) => {
                            if (err) return res.status(500).json({ message: "❌ Erreur lors de l'ajout des produits à la commande" });

                                    // Ajouter l'expédition
                                    db.query(
                                        "INSERT INTO expeditions (commande_id, adresse_livraison, transporteur, date_expedition, date_livraison_estimee) VALUES (?, ?, ?, NULL, DATE_ADD(NOW(), INTERVAL 5 DAY))",
                                        [commande_id, adresse_livraison, transporteur],
                                        (err) => {
                                            if (err) return res.status(500).json({ message: "❌ Erreur lors de l'ajout de l'expédition" });

                                            // Vider le panier du client
                                            db.query(
                                                "DELETE FROM panier WHERE client_id = ?",
                                                [client_id],
                                                (err) => {
                                                    if (err) return res.status(500).json({ message: "❌ Erreur lors de la suppression du panier" });

                                                    res.json({ message: "✅ Commande validée avec succès", commande_id });
                                                }
                                            );
                                        }
                                    );
                        }
                    );
                }
            );
        }
    );
});

/**
 * ➤ ROUTE : Modification du mot de passe
 * ➤ URL : PUT /api/clients/newPassword/:id
 * ➤ Body attendu (JSON) :
 * {
 *     "last_mdp": "test",
 *     "new_mdp": "test2"
 * }
 */
router.put("/clients/nouveauMdp/:id", (req, res) => {
    console.log("Données reçues :", req.body); // Vérifie ce qui est reçu

    const id = req.params.id;
    const { last_mdp, new_mdp } = req.body;

    db.query("SELECT mot_de_passe FROM utilisateurs WHERE id = ?", [id], (err, result) => {
        if (err) return res.status(500).json('Erreur serveur');
        if (result.length === 0) return res.status(404).json({ message: "❌ Utilisateur introuvable" });

        // Comparer les mots de passe
        bcrypt.compare(last_mdp, result[0].mot_de_passe, (err, isMatch) => {
            if (err) return res.status(500).json({message:'❌ Erreur serveur'});

            console.log("Mot de passe en base :", result[0].mot_de_passe);
            console.log("Mot de passe entré :", last_mdp);
            console.log("Résultat de la comparaison :", isMatch);

            if (!isMatch) return res.status(401).json({message:'❌ Pas les mêmes mdp'});

            bcrypt.hash(new_mdp, 10, (err, hashMdp) => {
                if (err) {
                    return res.status(500).json("❌ Problème Hash")
                }

                db.query("UPDATE utilisateurs SET mot_de_passe = ? WHERE id = ?", [hashMdp], (err) => {
                    if (err) return res.status(500).json({ message: "❌ Erreur lors de la mise à jour du mot de passe" });

                    res.status(200).json({ message: "✅ Mot de passe changé avec succès !" });
                })
            })
        });
    });
});

/**
 * ➤ ROUTE : Récupérer l'historique des commandes d'un utilisateur
 */
router.get("/orders", (req, res) => {
    const { user_id } = req.query;

    if (!user_id) {
        return res.status(400).json({ message: "L'ID du client est requis." });
    }

    db.query(
        `SELECT c.id, c.total, c.statut, c.date_commande, d.produit_id, p.nom, d.quantite
         FROM commandes c
         JOIN details_commandes d ON c.id = d.commande_id
         JOIN produits p ON d.produit_id = p.id
         WHERE c.client_id = ?
         ORDER BY c.date_commande DESC`,
        [user_id],
        (err, result) => {
            if (err) {
                console.error("Erreur lors de la récupération des commandes :", err);
                return res.status(500).json({ message: "Erreur interne du serveur" });
            }

            if (result.length === 0) {
                return res.status(404).json({ message: "Aucune commande trouvée pour cet utilisateur." });
            }

            res.status(200).json(result);
        }
    );
});


/**
 * ➤ ROUTE PROTÉGÉE : Récupérer les commandes d'un client connecté
 */

module.exports = router;