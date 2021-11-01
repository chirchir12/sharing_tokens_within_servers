require('dotenv').config();

// get random access token  require('crypto').randomBytes(64).toString('hex')
// get express
const express = require('express')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

// config
app.use(express.json())

const users = [];
let refreshTokens = [];

app.post('/users', async (req, res) => {
    let username = req.body.username
    //console.log(req.body)
    const userFound = users.find(user => user.username === username);

    if (userFound) {
        return res.status(400).send('user with this username exist')
    }

    const hashpassword = await bcrypt.hash(req.body.password, 10);
    users.push({ username, hashpassword })

    return res.status(201).send({ username })
})

app.get('/users', async (req, res) => {

    return res.status(200).json(users)

})

app.post('/auth/login', async (req, res) => {
    const user = users.find(user => user.username === req.body.username)
    if (!user) {
        return res.status(400).send('User with this username not found')
    }

    if (await bcrypt.compare(req.body.password, user.hashpassword)) {
        let accessToken = generateAccessToken({ user: req.body.username })
        let refreshToken = generateRefreshToken({ user: req.body.username })

        return res.status(200).json({ accessToken, refreshToken })


    } else {
        // password is wrong
        return res.status(401).send('incorrect password')
    }

})

app.post('/auth/refreshToken', (req, res) => {
    if (!refreshTokens.includes(req.body.token)) {
        return res.status(400).send('Refresh token is invalid')
    }

    refreshTokens = refreshTokens.filter(c => c !== req.body.token)
    let accessToken = generateAccessToken({ user: req.body.username })
    let refreshToken = generateRefreshToken({ user: req.body.username })

    return res.status(200).json({ accessToken, refreshToken })
})

app.delete('/logout', (req, res)=> {
    refreshTokens = refreshTokens.filter(token => token !== req.body.token)
    return res.status(204).send('Logout successfully')
})

// utils 

const generateAccessToken = (user) => {
    return jwt.sign(user, process.env.ACCESS_TOKEN_KEY, { expiresIn: '15m' })
}

const generateRefreshToken = (user) => {
    let refreshToken = jwt.sign(user, process.env.ACCESS_TOKEN_KEY, { expiresIn: '20m' })
    refreshTokens.push(refreshToken)
    return refreshToken
}


// get port number 
const port = process.env.PORT

// create server 
app.listen(port, () => {
    console.log(`authorization server listen on port ${port}`)
})