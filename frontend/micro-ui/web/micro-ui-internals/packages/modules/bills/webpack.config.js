const path = require('path');

module.exports = {
  entry: './src/Module.js',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'index.modern.js',
  },
  module: {
    rules: [
      {
        test: /\.m?js$/,
        exclude: /(node_modules|bower_components)/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: ['@babel/preset-env']
          }
        }
      }
    ]
  }
  

};