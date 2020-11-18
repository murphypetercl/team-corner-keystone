const { Keystone } = require('@keystonejs/keystone');
const { PasswordAuthStrategy } = require('@keystonejs/auth-password');
const { Text, Checkbox, Password, CalendarDay, DateTime, Relationship, Integer } = require('@keystonejs/fields');
const { MongoId } = require('@keystonejs/fields-mongoid');
const { atTracking, byTracking } = require('@keystonejs/list-plugins');
const { GraphQLApp } = require('@keystonejs/app-graphql');
const { AdminUIApp } = require('@keystonejs/app-admin-ui');

const { MongooseAdapter: Adapter } = require('@keystonejs/adapter-mongoose');
const mongoUriToConnectTo = process.env.NODE_ENV === 'production' ? (process.env.MONGO_URI) : ('mongodb://127.0.0.1:27017/team-corner');
const adapterConfig = { mongoUri: mongoUriToConnectTo };

const PROJECT_NAME = "Team Corner";
const initialiseData = require('./initial-data');

const keystone = new Keystone({
  name: PROJECT_NAME,
  adapter: new Adapter(adapterConfig),
  onConnect: initialiseData,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
    sameSite: false,
  },
  // Required for production mode
  cookieSecret: 'This is a very secret very-secret!!!!!'
});

// Access control functions
const userIsAdmin = ({ authentication: { item: user } }) => Boolean(user && user.isAdmin);
const userIsMember = ({ authentication: { item: user } }) => Boolean(user && user.isMember);
const userOwnsItem = ({ authentication: { item: user } }) => {
  if (!user) {
    return false;
  }
  return { id: user.id };
};

const userIsAdminOrOwner = auth => {
  const isAdmin = access.userIsAdmin(auth);
  const isOwner = access.userOwnsItem(auth);
  return isAdmin ? isAdmin : isOwner;
};

const access = { userIsAdmin, userIsMember, userOwnsItem, userIsAdminOrOwner };

keystone.createList('User', {
  fields: {
    firstName: { type: Text },
    lastName: { type: Text },
    email: {
      type: Text,
      isUnique: true,
    },
    isAdmin: {
      type: Checkbox,
      // Field-level access controls
      // Here, we set more restrictive field access so a non-admin cannot make themselves admin.
      access: {
        update: access.userIsAdmin,
      },
    },
    isMember: {
      type: Checkbox
    },
    password: {
      type: Password,
    },
  },
  // List-level access controls
  access: {
    read: access.userIsAdminOrOwner,
    update: access.userIsAdminOrOwner,
    // create: access.userIsAdminOrOwner,
    delete: access.userIsAdmin,
    auth: true,
  },
});

keystone.createList('Event', {
  fields: {
    eventType: { type: Text, isRequired: true },
    dateTime: {  
      type: DateTime,
      format: 'MM/DD/YYYY hh:mm A',
      yearRangeFrom: 2020,
      yearRangeTo: 9999,
      yearPickerType: 'auto',
    },
    location: { type: Text, isRequired: false },
    notes: { type: Text, isRequired: false },
  },
  // List-level access controls
  access: {
    read: access.userIsMember,
    update: access.userIsAdminOrOwner,
    create: access.userIsAdmin,
    delete: access.userIsAdmin,
    auth: true,
  },
  plugins: [
    atTracking({
    }),
    byTracking({
    }),
  ],

});

keystone.createList('Game', {
  fields: {
    team: { type: Relationship, ref: 'Team.games', many: false },
    competition: { type: Text, isRequired: true, defaultValue: 'League',  },
    opposition: { type: Text, isRequired: true },
    venue: { type: Text, isRequired: true },
    date: {  type: CalendarDay,
      format: 'Do MMMM YYYY',
      yearRangeFrom: 2020,
    },
    gameLogs: { type: Relationship, ref: 'GameLog', many: true},
    gameStatSummary: { type: Relationship, ref: 'GameStatSummary', many: false},
    gameLineOut: {type: Relationship, ref: 'GamePlayer', many: true}
  },
  // List-level access controls
  access: {
    read: access.userIsMember,
    update: access.userIsAdminOrOwner,
    create: access.userIsAdmin,
    delete: access.userIsAdmin,
    auth: true,
  },

  plugins: [
    atTracking({
    }),
    byTracking({
    }),
  ],

});

keystone.createList('GamePlayer', {
  fields: {
    gameId: { type: MongoId, isRequired: true },
    number: { type: Integer, isRequired: true },
    player: { type: Relationship, ref: 'Player', many: false, isRequired: true }
  },
  // List-level access controls
  access: {
    read: access.userIsMember,
    update: access.userIsAdminOrOwner,
    create: access.userIsAdmin,
    delete: access.userIsAdmin,
    auth: true,
  },
  plugins: [
    atTracking({
    }),
    byTracking({
    }),
  ],

});

keystone.createList('GameLog', {
  fields: {
    team: { type: Text, isRequired: true,  },
    playerNumber: { type: Text, isRequired: true },
    playerName: { type: Text, isRequired: true },
    stat: { type: Text, isRequired: true },
    gameTimeMin: { type: Text, isRequired: true },
    gameTimeSec: { type: Text, isRequired: true },
    formattedTime: { type: Text, isRequired: true },
    half: { type: Text, isRequired: true },
    gameId: {type: MongoId, isRequired: true },
    x: { type: Text },
    y: { type: Text },
  },
  // List-level access controls
  access: {
    read: access.userIsMember,
    update: access.userIsAdminOrOwner,
    create: access.userIsAdmin,
    delete: access.userIsAdmin,
    auth: true,
  },

  plugins: [
    atTracking({
    }),
    byTracking({
    }),
  ],

});

keystone.createList('Organization', {
  fields: {
    name: { type: Text, isRequired: true },
    webSite: { type: Text, isRequired: false },
    teams: { type: Relationship, ref: 'Team.organization', many: true},
    users: { type: Relationship, ref: 'User', many: true},
  },
  // List-level access controls
  access: {
    read: access.userIsMember,
    update: access.userIsAdminOrOwner,
    create: access.userIsAdmin,
    delete: access.userIsAdmin,
    auth: true,
  },
  plugins: [
    atTracking({
    }),
    byTracking({
    }),
  ],

});


keystone.createList('Team', {
  fields: {
    name: { type: Text, isRequired: true },
    organization: { type: Relationship, ref: 'Organization.teams', many: false },
    users: { type: Relationship, ref: 'User', many: true },
    players: { type: Relationship, ref: 'Player', many: true },
    games: { type: Relationship, ref: 'Game.team', many: true },
  },
  // List-level access controls
  access: {
    read: access.userIsMember,
    update: access.userIsAdminOrOwner,
    create: access.userIsAdmin,
    delete: access.userIsAdmin,
    auth: true,
  },
  plugins: [
    atTracking({
    }),
    byTracking({
    }),
  ],

});

keystone.createList('Player', {
  fields: {
    firstName: { type: Text, isRequired: true },
    lastName: { type: Text, isRequired: true },
  },
  // List-level access controls
  access: {
    read: access.userIsMember,
    update: access.userIsAdminOrOwner,
    create: access.userIsAdmin,
    delete: access.userIsAdmin,
    auth: true,
  },

  plugins: [
    atTracking({
    }),
    byTracking({
    }),
  ],

});

keystone.createList('GameStatSummary', {
  fields: {
    goalsForSelf: { type: Integer, isRequired: true, defaultValue: 0, label: 'Goals for Castlelyons' },
    pointsForSelf: { type: Integer, isRequired: true, defaultValue: 0, label: 'Points for Castlelyons' },
    goalsForOpposition: { type: Integer, isRequired: true, defaultValue: 0 },
    pointsForOpposition: { type: Integer, isRequired: true, defaultValue: 0 },
    hookBlock: { type: Integer, isRequired: true, defaultValue: 0, label: 'Hooks & Blocks' },
    turnover: { type: Integer, isRequired: true, defaultValue: 0, label: 'Turnovers' },
    turnoverWon: { type: Integer, isRequired: true, defaultValue: 0, label: 'Turnovers Won' },
    turnoverLost: { type: Integer, isRequired: true, defaultValue: 0, label: 'Turnovers Lost' },
    interception: { type: Integer, isRequired: true, defaultValue: 0, label: 'Interceptions' },
    looseBall: { type: Integer, isRequired: true, defaultValue: 0, label: 'Loose Balls won by Castlelyons' },
    homePuckoutWonH1: { type: Integer, isRequired: true, defaultValue: 0, label: 'Castlelyons Puckouts won by Castlelyons in the First Half' },
    homePuckoutLostH1: { type: Integer, isRequired: true, defaultValue: 0, label: 'Castlelyons Puckouts won by Opposition in the First Half' },
    homePuckoutWonH2: { type: Integer, isRequired: true, defaultValue: 0, label: 'Castlelyons Puckouts won by Castlelyons in the Second Half' },
    homePuckoutLostH2: { type: Integer, isRequired: true, defaultValue: 0, label: 'Castlelyons Puckouts won by Opposition in the Second Half' },
    oppositionPuckoutWonH1: { type: Integer, isRequired: true, defaultValue: 0, label: 'Opposition Puckouts won by Castlelyons in the First Half' },
    oppositionPuckoutLostH1: { type: Integer, isRequired: true, defaultValue: 0, label: 'Opposition Puckouts won by Opposition in the First Half' },
    oppositionPuckoutWonH2: { type: Integer, isRequired: true, defaultValue: 0, label: 'Opposition Puckouts won by Castlelyons in the Second Half' },
    oppositionPuckoutLostH2: { type: Integer, isRequired: true, defaultValue: 0, label: 'Opposition Puckouts won by Opposition in the Second Half' },
    scoresFromPlayH1: { type: Integer, isRequired: true, defaultValue: 0, label: 'Scores from play in the First Half' },
    shotsFromPlayH1: { type: Integer, isRequired: true, defaultValue: 0, label: 'Shots from play in the First Half' },
    scoresFromPlayH2: { type: Integer, isRequired: true, defaultValue: 0, label: 'Scores from play in the Second Half' },
    shotsFromPlayH2: { type: Integer, isRequired: true, defaultValue: 0, label: 'Shots from play in the Second Half' },
    scoresFromFrees: { type: Integer, isRequired: true, defaultValue: 0, label: 'Scores from frees' },
    shotsFromFrees: { type: Integer, isRequired: true, defaultValue: 0, label: 'Shots from frees' },
    scoresFrom65s: { type: Integer, isRequired: true, defaultValue: 0, label: 'Scores from 65s' },
    shotsFrom65s: { type: Integer, isRequired: true, defaultValue: 0, label: 'Shots from 65s' },
    freesWon: { type: Integer, isRequired: true, defaultValue: 0, label: 'Frees won by Castlelyons' },
    freesConceded: { type: Integer, isRequired: true, defaultValue: 0, label: 'Frees conceded by Castlelyons' },
    yellowCards: { type: Integer, isRequired: true, defaultValue: 0, label: 'Yellow cards for Castlelyons' },
    redCards: { type: Integer, isRequired: true, defaultValue: 0, label: 'Red cards for Castlelyons' },
    gameId: {type: MongoId, isRequired: true }
  },
  // List-level access controls
  access: {
    read: access.userIsMember,
    update: access.userIsAdminOrOwner,
    create: access.userIsAdmin,
    delete: access.userIsAdmin,
    auth: true,
  },

  plugins: [
    atTracking({
    }),
    byTracking({
    }),
  ],

});




const authStrategy = keystone.createAuthStrategy({
  type: PasswordAuthStrategy,
  list: 'User',
});


const apps = [
    new GraphQLApp(),
    new AdminUIApp({
        enableDefaultRoute: true,
        authStrategy,
    }),
];

  module.exports = {
    keystone,
    apps,
    configureExpress: app => {
      // Required for production mode to use secure cookies
      app.set('trust proxy', 1);
    },
  };
