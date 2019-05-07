module.exports = {
  dev: {
    app_callback: "localhost:8080"
  },
  production: {
    app_callback: "url"
  },
  common: {
    port: "8080",
    googleClientId: "",
    googleClientSecret: "",
    mongodbLink: "mongodb://localhost:27017/loginapp"
  }
};