const jwt = require("jsonwebtoken");

require("dotenv").config();

// verifying customers
const verifyTokenCustomer = (req, res, next) => {
  const token =
    req.body.token || req.query.token || req.headers["authorization"];
  if (!token) {
    return res.status(403).send("A token is required for authentication");
  }
  try {
    const decoded = jwt.verify(token, process.env.TOKEN_KEY);

    if(decoded.Admin != 0){
        return res.status(401).send("Invalid Token");
    }
    req.user = decoded;

  } catch (err) {
    return res.status(401).send("Invalid Token");
  }
  return next();
};
// verifying admin
const verifyTokenAdmin = (req, res, next) => {
  const token =
    req.body.token || req.query.token || req.headers["authorization"];

  if (!token) {
    return res.status(403).send("A token is required for authentication");
  }
  try {
    const decoded = jwt.verify(token, process.env.TOKEN_KEY);
    if(decoded.Admin != 1){
        return res.status(401).send("Invalid Token");
    }
    req.user = decoded;
  } catch (err) {
    return res.status(401).send("Invalid Token");
  }
  return next();
};

module.exports = {
  verifyTokenCustomer,
  verifyTokenAdmin,
};
