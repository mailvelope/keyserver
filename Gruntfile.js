'use strict';

module.exports = function(grunt) {

  grunt.initConfig({
    jshint: {
      all: ['*.js', 'src/**/*.js', 'test/**/*.js'],
      options: {
        jshintrc: '.jshintrc',
        ignores: ['src/static/js/*.min.js']
      }
    },

    jscs: {
      src: ['*.js', 'src/**/*.js', 'test/**/*.js'],
      options: {
        config: ".jscsrc",
        esnext: true, // If you use ES6 http://jscs.info/overview.html#esnext
        verbose: true, // If you need output with rule names http://jscs.info/overview.html#verbose
      }
    },

    mochaTest: {
      test: {
        options: {
          reporter: 'spec'
        },
        src: [
          'test/unit/*.js',
          'test/integration/*.js',
        ]
      }
    }
  });

  // Load the plugin(s)
  grunt.loadNpmTasks('grunt-contrib-jshint');
  grunt.loadNpmTasks('grunt-jscs');
  grunt.loadNpmTasks('grunt-mocha-test');

  // Default task(s).
  grunt.registerTask('test', ['jshint', 'jscs', 'mochaTest']);

};