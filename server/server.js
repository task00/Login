import express, { response } from 'express';
import mysql from 'mysql';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import cookieParser from 'cookie-parser';
const salt = 10;

const app =express();

// const server = express();


app.use(express.json());
app.use(cors({
    origin: ["http://localhost:3000"],
    methods: ["POST", "GET"],
    credentials: true
}));
app.use(cookieParser());

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password:"",
    database: "signup"
})

const verifyUser = (req,res,next) =>{
    const token = req.cookies.token;
    if(!token){
        return res.json({Error: "you are not authentication"});
    }else{
        jwt.verify(token, "jwt-secret-key",(err,decoded) => {
            if(err){
                return res.json({Error: "Token is not okey"});
            }else{
                req.name = decoded.name;
                next();
            }
        })
    }
}

app.get('/',verifyUser ,(req, res)=>{
    return res.json({Status: "Success", name: req.name});

})

app.post('/register' ,(req,res) => {
     const sql = "INSERT INTO sig (`name`,`email`,`password`) VALUES (?)";
     bcrypt.hash(req.body.password.toString(), salt,(err, hash) =>{
        if(err) return res.json({Error: "Error for hashing password"})

        const values=[
            req.body.name,
            req.body.email,
            hash
         ]

         db.query(sql,[values],(err,result)=>{

            
            if(err) return res.json({Error: "Inserting data error in server"});
            return res.json({status: "Success"});
        //   else  return res.send( "Success");
         })
     })
    
})
app.post('/login', (req,res) => {
    const sql ="SELECT * FROM sig WHERE email =?";
    db.query(sql,[req.body.email], (err,data) => {
        if(err)  return res.json({Error: "Login error in server"});
        if(data.length > 0){
            bcrypt.compare(req.body.password.toString(), data[0].password, (err,response)=>{
            // bcrypt.compare( data[0].password,req.body.password.toString(), (err,response)=>{

            if(err) return res.json({Error: "Password compare error"});
                console.log(response);
                if(response){
                    const name = data[0].name;
                    const token = jwt.sign({name}, "jwt-secret-key",{expiresIn: '1d'});
                    res.cookie('token',token);
                    return res.json({status : "Success"});
                }else{
                    
                    return res.json({Error: "Password not matched"})
                }
     })
        }else{
            return res.json({Error: "No email existed"});
        }
    })
})

app.listen(8081,() =>{
    console.log("Running..")

})