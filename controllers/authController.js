//Authentication and authorization are critical components of any security framework, ensuring that only legitimate users gain access to systems and that their actions are controlled according to their permissions.

//Authentication=> purpose is to confirm the identity of a user or system while
//Authorization=> control access to resources and define what authenticated users can do.

const usersDB = {
  users: require("../model/users.json"),
  setUsers: function (data) {
    this.users = data;
  },
};

const bcrypt = require("bcrypt");

const jwt = require("jsonwebtoken");
require("dotenv").config();
const fsPromises = require("fs").promises;
const path = require("path");

const handleLogin = async (req, res) => {
  const { user, pwd } = req.body;
  if (!user || !pwd)
    return res
      .status(400)
      .json({ message: "Username and password are required!!!" }); //Username & password error message

  const foundUser = usersDB.users.find((person) => person.username === user);

  if (!foundUser) return res.sendStatus(401); // unauthorized

  const match = await bcrypt.compare(pwd, foundUser.password);

  if (match) {
    
    
    
    // create JWTs
    const accessToken = jwt.sign(
      { username: foundUser.username },
      process.env.ACCESS_TOKEN_SECRET,
      {expiresIn: '60s'}
    );
    const refreshToken = jwt.sign(
      { username: foundUser.username },
      process.env.REFRESH_TOKEN_SECRET,  
      {expiresIn: '1d'}
    );

    const otherUsers = usersDB.users.filter(person => person.username === foundUser.username)
    const currentUser = {...foundUser, refreshToken};
    usersDB.setUsers([...otherUsers, currentUser]);
    await fsPromises.writeFile(
      path.join(__dirname, '..', 'model', 'users.json'),
      JSON.stringify(usersDB.users)
    )


    res.cookie('jwt', refreshToken, {httpOnly: true, maxAge: 24 * 60 * 60 * 1000 })
    res.json({ accessToken
      // success: `User ${user} is logged in Successfully!!!`,
    }); // Success message thrw when Successfully logged in
  } else {
    res.sendStatus(401);
  }
};

module.exports = {
  handleLogin,
};
