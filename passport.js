var mongoose = require('mongoose');
var User = mongoose.model('User');
// Estrategia de autenticación con Twitter
var TwitterStrategy = require('passport-twitter').Strategy;
// Estrategia de autenticación con Facebook
var FacebookStrategy = require('passport-facebook').Strategy;

var GoogleStrategy = require('passport-google-oauth2').Strategy;

var AzureAdOAuth2Strategy = require('passport-azure-ad-oauth2').Strategy;

var jwt = require('jwt-simple');

// Fichero de configuración donde se encuentran las API keys
// Este archivo no debe subirse a GitHub ya que contiene datos
// que pueden comprometer la seguridad de la aplicación.
var config = require('./config');


// Exportamos como módulo las funciones de passport, de manera que
// podamos utilizarlas en otras partes de la aplicación.
// De esta manera, mantenemos el código separado en varios archivos
// logrando que sea más manejable.
module.exports = function(passport) {

	// Serializa al usuario para almacenarlo en la sesión
	passport.serializeUser(function(user, done) {
		done(null, user);
	});

	// Deserializa el objeto usuario almacenado en la sesión para
	// poder utilizarlo
	passport.deserializeUser(function(obj, done) {
		done(null, obj);
	});

	// Configuración del autenticado con Twitter
	passport.use(new TwitterStrategy({
		consumerKey		 : config.twitter.key,
		consumerSecret	: config.twitter.secret,
		callbackURL		 : '/auth/twitter/callback'
	}, function(accessToken, refreshToken, profile, done) {
		// Busca en la base de datos si el usuario ya se autenticó en otro
		// momento y ya está almacenado en ella
		User.findOne({provider_id: profile.id}, function(err, user) {
			if(err) throw(err);
			// Si existe en la Base de Datos, lo devuelve
			if(!err && user!= null) return done(null, user);

			// Si no existe crea un nuevo objecto usuario
			var user = new User({
				provider_id	: profile.id,
				provider		 : profile.provider,
				name				 : profile.displayName,
				photo				: profile.photos[0].value
			});
			//...y lo almacena en la base de datos
			user.save(function(err) {
				if(err) throw err;
				done(null, user);
			});
		});
	}));

	// Configuración del autenticado con Google
	passport.use(new GoogleStrategy({
		clientID:  config.google.id,
    clientSecret: config.google.secret,
    callbackURL: "/auth/google/callback",
    passReqToCallback   : true
	  },
		function(request, accessToken, refreshToken, profile, done) {
	    // User.findOrCreate({ googleId: profile.id }, function (err, user) {
	    //   return done(err, user);
	    // });

			console.log("profile " + JSON.stringify(profile));
			User.findOne({provider_id: profile.id}, function(err, user) {
				if(err) throw(err);
				if(!err && user!= null) return done(null, user);

				// Al igual que antes, si el usuario ya existe lo devuelve
				// y si no, lo crea y salva en la base de datos
				var user = new User({
					provider_id	: profile.id,
					provider		 : profile.provider,
					name				 : user.name,
					photo				: user.photos[0].value
				});
				user.save(function(err) {
					if(err) throw err;
					done(null, user);
				});
			});

	  }
 ));

 passport.use(new AzureAdOAuth2Strategy({
   clientID: config.microsoft.id,
   clientSecret: config.microsoft.secret,
   callbackURL: 'http://localhost:5000/auth/azureadoauth2/callback',
   resource: '00000003-0000-0000-c000-000000000000'//,
   //tenant: 'contoso.onmicrosoft.com'
 },
 function (accessToken, refresh_token, params, profile, done) {

	var waadProfile = profile || jwt.decode(params.id_token);
	//  console.log("accessToken --> " + jwt.decode(refresh_token, accessToken));
	//  console.log("refresh_token --> " + refresh_token);

	 User.findOne({provider_id:  waadProfile.upn}, function(err, user) {
		 if(err) throw(err);
		 if(!err && user!= null) return done(null, user);



		 // Al igual que antes, si el usuario ya existe lo devuelve
		 // y si no, lo crea y salva en la base de datos
		 var user = new User({
			 provider_id	:  waadProfile.upn,
			 provider		 : profile.provider,
			 name				 : profile.displayName//,
			 //photo				: profile.photos[0].value
		 });
		 user.save(function(err) {
			 if(err) throw err;
			 done(null, user);
		 });
	 });

 }));


	// Configuración del autenticado con Facebook
	passport.use(new FacebookStrategy({
		clientID			: config.facebook.id,
		clientSecret	: config.facebook.secret,
		callbackURL	 : '/auth/facebook/callback',
		profileFields : ['id', 'displayName', /*'provider',*/ 'photos']
	}, function(accessToken, refreshToken, profile, done) {
		// El campo 'profileFields' nos permite que los campos que almacenamos
		// se llamen igual tanto para si el usuario se autentica por Twitter o
		// por Facebook, ya que cada proveedor entrega los datos en el JSON con
		// un nombre diferente.
		// Passport esto lo sabe y nos lo pone más sencillo con ese campo
		User.findOne({provider_id: profile.id}, function(err, user) {
			if(err) throw(err);
			if(!err && user!= null) return done(null, user);

			// Al igual que antes, si el usuario ya existe lo devuelve
			// y si no, lo crea y salva en la base de datos
			var user = new User({
				provider_id	: profile.id,
				provider		 : profile.provider,
				name				 : profile.displayName,
				photo				: profile.photos[0].value
			});
			user.save(function(err) {
				if(err) throw err;
				done(null, user);
			});
		});
	}));
};
