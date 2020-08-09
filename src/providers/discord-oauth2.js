const DiscordOauth2 = require("discord-oauth2");
let oauth

const debug = (event, ...rest) => {
  if(process.env.DEBUG)
    console.log({event, rest:JSON.stringify(rest)})
}

const init = ({clientId, clientSecret, redirectUri}) => {
  oauth = new DiscordOauth2({
    clientId: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    redirectUri: process.env.REDIRECT_URI,
  });
}

const authorize = ({code, grantType, scope}) => new Promise(async(resolve,reject) => {
  console.log({event: 'authorize', code, grant_type})
  const tokenRequestResponse = await oauth.tokenRequest({
    code, 
    scope,
    grantType
  }).catch(console.error);

  if(!tokenRequestResponse){
    resolve(false)
    return
  }

  debug('token-request-response', { tokenRequestResponse })

  let access_token, expires_in
  try{
    ({access_token, expires_in} = tokenRequestResponse)
  }catch(ex){
    console.log({event:'error-destructuring-token-request-response', tokenRequestResponse})
    resolve(false)
    return
  }
  
  if(!(access_token && expires_in)){
    console.log({event: 'auth-failure', tokenRequestResponse})
    resolve(false)
    return
  }
    
  const userClaims = await oauth.getUser(access_token).catch(console.error)
  if(!userClaims){
    console.log({event: 'getUser-failure', userClaims, tokenRequestResponse})
    resolve(false)
    return
  }

  debug('get-user-claims-ok', { userClaims, tokenRequestResponse })

  resolve(userClaims)
  return
})


module.exports = { init, authorize }