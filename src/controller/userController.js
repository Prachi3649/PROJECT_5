const userModel = require("../model/userModel")
const validator = require("../validator/validator")
const aws = require("./aws")
const jwt = require("jsonwebtoken")

const register = async (req, res) => {
    try{
        // const data1 = req.body.data;
        
        // const data = JSON.parse(data1)
        const data = req.body
        // console.log(data)
        // const file = req.files
        if (!validator.isValidObject(data)){
            return res.status(400).send({status: false, message: "please fill all required fields"})
        }
        const{fname, lname, email, phone, password, address} = data
        // address = JSON.parse(address)
        // console.log(password)
        // console.log(address)
        const {shipping, billing} = address
        if (!validator.isValidObject(shipping)){
            return res.status(400).send({status: false, message: "please fill all required fields in shipping"})
        }
        if (!validator.isValidObject(billing)){
            return res.status(400).send({status: false, message: "please fill all required fields billing"})
        }
        if(!validator.isValid(fname)){
            return res.status(400).send({status: false, message: "please enter your first name"})
        }
        if(!validator.isValid(lname)){
            return res.status(400).send({status: false, message: "please enter your last name"})
        }
        if(!validator.isValid(email)){
            return res.status(400).send({status: false, message: "please enter your email"})
        }
        if(!validator.isValidEmail(email)){
            return res.status(400).send({status: false, message: "please enter valid email"})
        }
        const isEmailInUse = await userModel.findOne({email: email})
        if(isEmailInUse) {
            return res.status(400).send({status:false, message: "email already registered, enter different email"})
        }
        if(!validator.isValid(password)){
            return res.status(400).send({status: false, message: "please enter password"})
        }
        if(!validator.isValidPW(password)){
            return res.status(400).send({status: false, message: "please enter valid password, between 8 to 15 characters"})
        }
        if (!validator.isValidPhone(phone)){
            return res.status(400).send({status: false, message: "please enter valid phone number"})
        }
        const isPhoneInUse = await userModel.findOne({phone: phone})
        if(isPhoneInUse) {
            return res.status(400).send({status:false, message: "phone number already registered, enter different number"})
        }
        if(!validator.isValid(shipping.street)){
            return res.status(400).send({status: false, message: "please enter street name"})
        }
        if(!validator.isValid(shipping.city)){
            return res.status(400).send({status: false, message: "please enter name of city"})
        }
        if(!validator.isValid(shipping.pincode)){
            return res.status(400).send({status: false, message: "please enter pincode"})
        }
        if(!validator.isValid(billing.street)){
            return res.status(400).send({status: false, message: "please enter street name"})
        }
        if(!validator.isValid(billing.city)){
            return res.status(400).send({status: false, message: "please enter name of city"})
        }
        if(!validator.isValid(billing.pincode)){
            return res.status(400).send({status: false, message: "please enter pincode"})
        }
        const link = await getProfileImgLink(req, res)
        data.profileImage = link
        // return res.send({data: data})
        const user = await userModel.create(data)
        return res.status(201).send({status: true, message: 'Success', data: user})
    }catch(error){
        return res.status(500).send({status: false, message: error.message})
    }
}

const getUserProfile = async function(req,res){
    try{  
        let userId = req.params.userId;
        if(!(validator.isValid(userId) && validator.isValidObjectId(userId))) {
          return res.status(400).send({status: false, msg: "user  Id not valid"})
      }
      let getUserProfile = await userModel.findById(userId);
      if(!getUserProfile){
          return res.status(404).send({status:false, msg:"User Not Found"})
      }
     return res.status(200).send({status:true, message: "User profile details",data:getUserProfile})
  }catch (err) {
      console.log("This is the error :", err.message);
      return res.status(500).send({ msg: "Error", error: err.message });
    }
}

const userlogin = async function (req, res){
    try{      
      const body = req.body;
      //// check body  provied or not
      if(!validator.isValidObject(body)){
          return res.status(404).send ({status:false, msg :"Please provide body"})
      }
      const emailId = req.body.email
      const password = req.body.password
      //check user exist or not
      if(!(emailId || password)) {
        return res.status(400).send ({ status : false, msg: "uer does not exist"})
      } 
     // check email provied or not
      if(!validator.isValid(emailId)){
            return res.status(400).send ({status:false , msg: "plese provide email_Id"})    
      }
      // check by regex
      if(!(validator.isValidEmail(emailId))) {
          return res.status(400).send ({status:false, msg: "please provide valid eamil with sign"})
      }
      // check password provied or not
      if(!validator.isValid(password)){
          return res.status(400).send ({status:false, msg: "please provide valid password"})
      }
     //check by regex
      // if (!(validator.isValidPassword(password))) {
      //     return res.status(400).send ({status:false, msg: "please provide valid password with valid sign"})
      // }
      const login = await userModel.findOne({ email: emailId, password: password})
      if(!login) {
          return res.status(400).send ({ status: false , msg : "username or the password is not corerct"})
      }
      let token = jwt.sign(
          {
              userId: login._id,
              iat: Math.floor(Date.now() / 1000),
              exp: Math.floor(Date.now() / 1000) + 2*60*60
         
          }, "projectfourgroup30"
      );
         res.status(200).setHeader ("api-token-key", token)
          return res.status(200).send ({ status:true, msg: "created successfully" ,data:{userId: login._id, Token: token}})
    } 
      catch (error) {
        return res.status(500).send({ ERROR: error.message })
    }
};
  
const getProfileImgLink = async (req, res) => {
    try{
        let files = req.files
        if(files && files.length > 0){
            let uploadedFileURL = await aws.uploadFile(files[0])
            // return res.status(201).send({status: true, message: "file uploaded succesfully", data: uploadedFileURL})
            return uploadedFileURL
        }else{
            return res.status(400).send({ msg: "No file found" })
        }
    }catch(error){
        return res.status(500).send({status: false, message: error.message })
    }
}

module.exports.register = register
module.exports.getUserProfile = getUserProfile;
module.exports.userlogin = userlogin