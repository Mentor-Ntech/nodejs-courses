//Authentication and authorization are critical components of any security framework, ensuring that only legitimate users gain access to systems and that their actions are controlled according to their permissions.

//Authentication=> purpose is to confirm the identity of a user or system while
//Authorization=> control access to resources and define what authenticated users can do.

const usersDB = {
    users: require("../model/users.json"),
    setUsers: function (data) {
      this.users = data;
    },
  };
  
  
  const jwt = require("jsonwebtoken");
  require("dotenv").config();
  
  
  const handleRefreshToken =  (req, res) => {
    const cookies = req.cookies
    if (!cookies?.jwt)
      return res.sendStatus(401)
    
    console.log(cookies.jwt);

    const refreshToken = cookies.jwt;
  
    const foundUser = usersDB.users.find(person => person.refreshToken === refreshToken);
  
    if (!foundUser) return res.sendStatus(403); // Forbidden
    
    //evaluate jwt
  
      jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        (err, decoded) => {
            if (err || foundUser.username !== decoded.username) return res.sendStatus(403);
            const accessToken =jwt.sign(
                {"username": decoded.username},
                process.env.ACCESS_TOKEN_SECRET,
                {expiresIn: '30s'}
            );

            res.json({accessToken})
        }
      )
      
    }
  module.exports = {
    handleRefreshToken,
  };
  