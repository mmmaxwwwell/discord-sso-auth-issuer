const express = require('express');
const fetch = require('node-fetch');
const btoa = require('btoa');
const { catchAsync } = require('../utils');

const registerCallback = (router) => {
  router.get('/callback', catchAsync(async (req, res) => {
    if (!req.query.code) throw new Error('NoCodeProvided');
    const code = req.query.code;
    const creds = btoa(`${CLIENT_ID}:${CLIENT_SECRET}`);
    const response = await fetch(`https://discordapp.com/api/oauth2/token?grant_type=authorization_code&code=${code}&redirect_uri=${redirect}`,
      {
        method: 'POST',
        headers: {
          Authorization: `Basic ${creds}`,
        },
      });
    const json = await response.json();
    res.redirect(`/?token=${json.access_token}`);
  }));
}

