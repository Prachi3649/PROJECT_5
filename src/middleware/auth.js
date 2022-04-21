const jwt = require("jsonwebtoken")
const validator = require("../validator/validator")

const authentication = async function  (req, res , next)
{
    try {
        const token = req.header('Authorization', 'Bearer Token')
        /**
          jwt.verify(token, secretkey, function (error, decode) {
      if (error) {
        //setHeader("Content-Type", "text/JSON")
        return res
          .status(400)
          .setHeader("Content-Type", "text/JSON")
          .send({ status: false, message: error.message });
      }
 */
        if(!token){
            return res.status(401).send({status:false , message:"Plz enter a token"})
        }
        let splitToken = token.split(' ')     // [ brearer, token ]
        let decodedToken = jwt.verify(splitToken[1], "projectfivegroup30")
        //check decoded Token
        if(!decodedToken){
            return  res.status(400).send ({status:false, message: "token is invalid"})
        }
        if (Date.now()>(decodedToken.exp)*1000) {
            return res.status(404).send({ status: false, message: `please login again because session is expired` })
        }
        next()
        }
    catch (error){
        return res.status(500).send ({ status:false , message: error.message})
    } 
}

const userAuthorization = async function(req, res, next){
    // let token = req.headers["authorization"];
    const token = req.header('Authorization', 'Bearer Token')
    if(!token){
        return res.status(400).send({status:false , message:"Plz enter a token"})
    }
    let splitToken = token.split(' ') // [bearer , token]
    let decodedToken = jwt.verify(splitToken[1], "projectfivegroup30")
    let userId = req.params.userId;
    let DuserId = decodedToken.userId;
    if(!(validator.isValid(userId)) && (validator.isValidObjectId(userId))){
      return res.status(400).send({status:false , message:"plz enter a valid userId"})  
    }
    if(userId != DuserId){
        return res.status(403).send({status:false , message:"You are not authorized"})
    }
    next()
}

module.exports.userAuthorization = userAuthorization;
module.exports.authentication = authentication
