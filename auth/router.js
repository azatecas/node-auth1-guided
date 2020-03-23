const bcrypt = require("bcryptjs");

const router = require("express").Router();

const Users = require("../users/users-model.js");

router.post("/register", (req, res) => {
    const userInfo = req.body;

    //the password will be hashed and re-hashed 2^8 times
    const ROUNDS = process.env.HASHING_ROUNDS || 16;
    const hash = bcrypt.hashSync(userInfo.password, ROUNDS);

    userInfo.password = hash;

    Users.add(userInfo)
        .then(user => {
            console.log('userInfo',userInfo)
            res.json(user);
        })
        .catch(err => res.send(err.message));
});

router.post("/login", (req, res) => {
    const { username, password } = req.body;

    Users
        .findBy({ username })
        .then(([ user ]) => {
            if(user && bcrypt.compareSync(password, user.password)) {
                // remember the client
                req.session.user = {
                    id: user.id,
                    username: user.username,
                }

                res.status(200).json({ hello: user});
            } else {
                res.status(401).json({ message: 'invalid credentials'})
            }
        })
        .catch(err => {
        res.status(500).json({ errorMessage: "error finding user"})
    })

});

router.get("/logout", (req, res) => {
    if(req.session) {
        req.session.destroy();
    } else {
        res.status(200).json({message: "already logged out"})
    }
})
module.exports = router;
