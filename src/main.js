var jwt = require('jsonwebtoken');
var discord = require('./providers/discord')
const express = require("express")
const provider = require(`./providers/${process.env.PROVIDER || 'discord-oauth2'}.js`)
const cookieParser = require("cookie-parser")
const app = express()
const HEADER_NAME = process.env.HEADER_NAME || "jwt_token";

const debug = (event, obj) => {
  if(process.env.DEBUG)
    console.log({event, obj})
}

const port = parseInt(process.env.PORT)

app.use(cookieParser())

app.get("/discord/callback", async (req, res, next) => {
  console.log(req)
  debug('callback-params', {params: req.params})
  const result = await provider.authorize({
    code: req.query.code,
    grantType: process.env.GRANT_TYPE,
    scope: process.env.SCOPE
  })

  if(!result){
    console.log({event:'oauth-result-error', result})
    res.status(401)
    res.end()
    return
  }
  
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
    console.log({event:'error-destructuring-get-user-response', result})
    res.status(401)
    res.end()
    return
  }

  let roles
  try{
    roles = await discord.getUserRoles(id)
  }catch(error){
    console.log({event:'error-getting-roles', id, username, discriminator, error })
    res.status(401)
    res.end()
    return
  }

  let forwardedFor, ip
  try{
    forwardedFor = req.headers['x-forwarded-for']
    ip = req.ip;
  } catch(error) {
    console.log({event:'error-getting-source-ip', id, username, discriminator, error })
    res.status(401)
    res.end()
    return
  }
  debug('headers', {headers: req.headers})
  try{
    const claims = {
      expires: Date.now() + parseInt(process.env.JWT_VALID_MINS) * 60000,
      id,
      username,
      mfa_enabled,
      locale,
      avatar,
      discriminator,
      public_flags,
      flags,
      roles,
      forwardedFor,
      ip,
      domain: process.env.JWT_DOMAIN
    }

    const jwt_token = jwt.sign(claims, process.env.KEY, {algorithm: 'HS384'});

    const options = { domain: process.env.JWT_DOMAIN, path: '/', secure: true, sameSite: 'Lax', httpOnly: true }
    debug('issuing-jwt', { claims, options, redirect: process.env.SUCCESS_REDIRECT })
    res.cookie(HEADER_NAME, jwt_token, options)
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
  debug('headers', {headers: req.headers})
  debug('params', {params: req.params})
  res.redirect(`https://discord.com/api/oauth2/authorize?client_id=${process.env.CLIENT_ID}&redirect_uri=${encodeURIComponent(process.env.REDIRECT_URI)}&response_type=${process.env.RESPONSE_TYPE}&scope=${process.env.SCOPE}&state=${encodeURI(req.headers.host)}${encodeURI(req.headers['x-original-uri'])}`)
  res.end()
})


provider.init({
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  redirectUri: process.env.REDIRECT_URI,
})

app.listen(port, () => console.log(`discord-sso-auth-issuer listening on port ${port}${process.env.DEBUG ? " with debug output" : ""}!`))
