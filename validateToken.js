require('dotenv').config();

const express = require('express')
const jwt = require("jsonwebtoken")
const port = process.env.POST_PORT
const app = express()

// config
app.use(express.json())

const validateToken = (req, res, next) => {
    const authHeader = req.headers['authorization']
    let token = authHeader.split(' ')[1]

    if(!token){
        return res.status(400).send('Invalid Token')
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_KEY, (err, user)=> {
        if(err){
            return res.status(401).send('Invalid Token')
        }
        req.user = user
        next()
    })
}

app.get("/posts", validateToken, (req, res) => {
    console.log("Token is valid")
    console.log(req.user)
    res.send(`${20} successfully accessed post`)
})

// utils 



// create server 
app.listen(port, () => {
    console.log(`authorization server listen on port ${port}`)
})