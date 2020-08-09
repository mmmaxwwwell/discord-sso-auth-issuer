let groupsLookup

const init = () => {
  groupsLookup = JSON.parse(process.env.POC_GROUPS)
}

const getGroups = async (user) => new Promise((resolve,reject) => {
  resolve(groupsLookup[user] || [])
})

module.exports = { init,  getGroups }