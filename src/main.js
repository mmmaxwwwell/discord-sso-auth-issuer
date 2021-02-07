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

const port = parseInt(process.env.ISSUER_PORT)

app.use(cookieParser())

app.get("/discord/callback", async (req, res, next) => {
  //validate signed state, get redirectURI
  let redirectURI
  try{
    const signed_state = jwt.verify(decodeURI(req.query.state), process.env.KEY, {algorithm: 'HS384'});
    if(!signed_state){
      console.log({event: 'signed-state-invalid', state: req.query.state})
      res.sendStatus(401)
      res.end()
      return
    }
    
    // const externalIp = "0.0.0.0"
    // if(signed_state.ip != externalIp){
    //   console.log({event: 'signed-state-ip-invalid', state: signed_state, externalIp})
    //   res.sendStatus(401)
    //   res.end()
    //   return
    // }

    if(signed_state.signedAt < Date.now() - (60 * 1000)){
      console.log({event: 'signed-state-timeout', state: signed_state, now: Date.now()})
      res.sendStatus(401)
      res.end()
      return
    }

    redirectURI = signed_state.redirect
    debug('validated-signed-state', {code: req.query.code, signed_state})
    if(!redirectURI){
      console.log({error: 'missing-redirect-uri', signed_state, state: req.query.state})
      res.sendStatus(401)
      res.end()
      return
    }
  }catch(ex){
    console.log({event: 'signed-state-val-exception', ex, signed_state})
  }

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

  if(!mfa_enabled){
    console.log({event:'mfa-not-enabled', result})
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
    }

    const jwt_token = jwt.sign(claims, process.env.KEY, {algorithm: 'HS384'});
    const options = { domain: process.env.DOMAIN, path: '/', secure: true, sameSite: 'Lax', httpOnly: true }
    debug('issuing-jwt', { claims, options, redirect: process.env.SUCCESS_REDIRECT })
    res.cookie(HEADER_NAME, jwt_token, options)
    res.redirect('https://' + redirectURI)
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
  const signed_state = jwt.sign({
    redirect: req.headers.host + req.headers['x-original-uri'],
    signedAt: Date.now()
  }, process.env.KEY, {algorithm: 'HS384'});
  res.redirect(`https://discord.com/api/oauth2/authorize?client_id=${process.env.CLIENT_ID}&redirect_uri=${encodeURIComponent(`https://${process.env.ISSUER_SUBDOMAIN}${process.env.DOMAIN}${process.env.REDIRECT_URI_PATH}`)}&response_type=${process.env.RESPONSE_TYPE}&scope=${process.env.SCOPE}&state=${encodeURI(signed_state)}`)
  res.end()
})

provider.init({
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  redirectUri: process.env.REDIRECT_URI,
})

app.listen(port, () => console.log(`discord-sso-auth-issuer listening on port ${port}${process.env.DEBUG ? " with debug output" : ""}!`))
