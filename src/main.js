var jwt = require('jsonwebtoken');
process.env.DEBUG = "express:*";
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
  try{
    const {
      access_token,
      expires_in,
      refresh_token,
      scope,
      token_type
    } = await oauth.tokenRequest({
      code: req.query.code,
      grantType: process.env.GRANT_TYPE,
    });

    const {
      id,
      username,
      mfa_enabled,
      locale,
      avatar,
      discriminator,
      public_flags,
      flags
    } = await oauth.getUser(access_token)

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

    res.cookie('jwt_token', jwt_token, { domain: "massive.games", path: '/', secure: true, sameSite: 'Lax', httpOnly: true })
    res.redirect(process.env.SUCCESS_REDIRECT)
  }catch(err){
    res.status(500);
    res.end();
    console.error(err)
    return
  }
  res.status(200);
  res.end();
})

app.get("/", function (req, res, next) {
  res.redirect(`https://discord.com/api/oauth2/authorize?client_id=${process.env.CLIENT_ID}&redirect_uri=${encodeURIComponent(process.env.REDIRECT_URI)}&response_type=${process.env.RESPONSE_TYPE}&scope=${process.env.SCOPE}`)
  res.end()
})

app.listen(port, () => console.log(`Example app listening on port ${port}!`));
