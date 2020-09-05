var jwt = require('jsonwebtoken');
const express = require("express")
const provider = require(`./providers/${process.env.PROVIDER || 'discord-oauth2'}.js`)
const cookieParser = require("cookie-parser")
const groupsProvider = require('./groupsProvider.js')
const app = express()

const debug = (event, obj) => {
  if(process.env.DEBUG)
    console.log({event, obj})
}

const port = parseInt(process.env.PORT)

app.use(cookieParser())

app.get("/discord/callback", async (req, res, next) => {
  
  const result = await provider.authorize({
    code: req.query.code,
    grantType: process.env.GRANT_TYPE,
    scope: process.env.SCOPE
  })
  
  debug('callback-validate-result', result)

  let id, username, mfa_enabled, locale, avatar, discriminator, public_flags, flags, expires_in
  try{
    ({
      id,
      username,
      mfa_enabled,
      locale,
      avatar,
      discriminator,
      public_flags,
      flags,
      expires_in
    } = result)
  }catch(error){
    console.log({event:'error-destructuring-get-user-repsonse', result})
    res.status(401);
    res.end();
    return
  }

  try{
    const groups = await groupsProvider.getGroups(`${username}#${discriminator}`)
    const claims = {
      expires: Date.now() + expires_in,
      id,
      username,
      mfa_enabled,
      locale,
      avatar,
      discriminator,
      public_flags,
      flags,
      admin: groups.includes("Admin"),
      moderator: groups.includes("Moderator"),
      groups
    }

    const jwt_token = jwt.sign(claims, process.env.KEY, {algorithm: 'HS384'});

    const options = { domain: process.env.JWT_DOMAIN, path: '/', secure: true, sameSite: 'Lax', httpOnly: true }
    debug('issuing-jwt', { claims, options, redirect: process.env.SUCCESS_REDIRECT })
    res.cookie('jwt_token', jwt_token, options)
    res.redirect(process.env.SUCCESS_REDIRECT)
    res.end()
    return
  }catch(error){
    console.log({event:'error-gen-jwt', error })
    res.status(401)
    res.end()
    return
  }
})

app.get("/", function (req, res, next) {
  res.redirect(`https://discord.com/api/oauth2/authorize?client_id=${process.env.CLIENT_ID}&redirect_uri=${encodeURIComponent(process.env.REDIRECT_URI)}&response_type=${process.env.RESPONSE_TYPE}&scope=${process.env.SCOPE}`)
  res.end()
})


provider.init({
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  redirectUri: process.env.REDIRECT_URI,
})
groupsProvider.init()
app.listen(port, () => console.log(`discord-sso-auth-issuer listening on port ${port}${process.env.DEBUG ? " with debug output" : ""}!`))
