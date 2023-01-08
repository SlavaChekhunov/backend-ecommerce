const router = require("express").Router();
const User = require("../models/User");
const CryptoJS = require("crypto-js");
const jwt = require("jsonwebtoken");

//REGISTER
//user sends us his username and password etc.
router.post("/register", async (req, res) => {
  const newUser = new User({
    username: req.body.username,
    email: req.body.email,
    password: CryptoJS.AES.encrypt(req.body.password, process.env.PASS_SEC).toString(),
  });
  //save is a promise which is async
  //right now we are pushing the password string to the db which is bad, so we need to encrypt it
  try {
    const savedUser = await newUser.save();
    res.status(200).json(savedUser);
  } catch (err) {
    //you can if there is no request for body, email/password, you can do error status 400...please enter password etc.
    res.status(500).json(err);
    console.log(err)
  }
});

//LOGIN

router.post("/login", async (req, res) => {
    //find user inside db
    //findOne bc only need one user, and return to me just the username
     try {
        const user = await User.findOne({ username: req.body.username });

        if(!user) 
        {
          return res.status(401).json("Wrong credentials!");
        }

        const hashedPassword = CryptoJS.AES.decrypt(
          user.password, 
          process.env.PASS_SEC
        );

        const OriginalPassword = hashedPassword.toString(CryptoJS.enc.Utf8);

        if (OriginalPassword !== req.body.password)
          {
            return res.status(401).json("Wrong credentials!");
          }


          const accessToken = jwt.sign({
            id: user.id,
            isAdmin: user.isAdmin,
          }, process.env.JWT_SEC,
            {expiresIn: "3d"}
          );

        const { password, ...others} = user._doc;

        res.status(200).json({...others, accessToken});
    } catch (err) {
        res.status(500).json(err)
        console.log(err)
    }
})



module.exports = router;
