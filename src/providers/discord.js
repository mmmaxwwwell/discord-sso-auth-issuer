const Discord = require('discord.js')
const client = new Discord.Client()

client.on('ready', () => {
  console.log(`Logged in as ${client.user.tag}!`)
})

client.login(process.env.DISCORD_TOKEN)

const getUserRoles = (id) => new Promise( async (resolve, reject) => {
  const guild = client.guilds.cache.get(process.env.AUTH_GUILD_ID)
  
  if(!guild)
    resolve(false)

  const member = await guild.members.fetch({user: id, force: true})
  if(!member)
    resolve(false)

  const roles = member.roles.cache.map(role => role.name)
  console.log({roles})
  resolve(roles)
})

module.exports = { getUserRoles }