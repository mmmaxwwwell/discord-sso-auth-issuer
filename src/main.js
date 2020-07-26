var jwt = require('jsonwebtoken');
const express = require("express")
const expressWs = require( "express-ws")
const cookieParser = require( "cookie-parser")
const { app, getWss, applyTo } = expressWs(express());
const DiscordOauth2 = require('discord-oauth2') 
const oauth = new DiscordOauth2({
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  redirectUri: process.env.REDIRECT_URI,
});

const port = parseInt(process.env.PORT);
app.use(cookieParser());

app.get("/discord/callback", async (req, res, next) => {
  
  const tokenRequestResponse = await oauth.tokenRequest({
    code: req.query.code,
    grantType: process.env.GRANT_TYPE,
  }).catch(console.error);

  const access_token = tokenRequestResponse.access_token
  const expires_in = tokenRequestResponse.expires_in
  
  if(!(access_token && expires_in)){
    console.log({event: 'auth-failure', tokenRequestResponse})
    res.status(401);
    res.end();
    return
  }
    
  const getUserResponse = await oauth.getUser(access_token).catch(console.error)

  try{
    const {
      id,
      username,
      mfa_enabled,
      locale,
      avatar,
      discriminator,
      public_flags,
      flags
    } = getUserResponse

    const jwt_token = jwt.sign({
      expires: Date.now() + expires_in,
      id,
      username,
      mfa_enabled,
      locale,
      avatar,
      discriminator,
      public_flags,
      flags
    }, process.env.KEY);

    res.cookie('jwt_token', jwt_token, { domain: process.env.JWT_DOMAIN, path: '/', secure: true, sameSite: 'Lax', httpOnly: true })
    res.redirect(process.env.SUCCESS_REDIRECT)
    res.status(200);
    res.end();
    return
  }catch(error){
    console.log({error, getUserResponse, tokenRequestResponse})
    res.status(401);
    res.end();
    return
  }
})

app.get("/", function (req, res, next) {
  res.redirect(`https://discord.com/api/oauth2/authorize?client_id=${process.env.CLIENT_ID}&redirect_uri=${encodeURIComponent(process.env.REDIRECT_URI)}&response_type=${process.env.RESPONSE_TYPE}&scope=${process.env.SCOPE}`)
  res.end()
})

app.listen(port, () => console.log(`Example app listening on port ${port}!`));
