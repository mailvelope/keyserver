'use strict';

module.exports = function(grunt) {

  grunt.initConfig({
    jshint: {
      all: ['*.js', 'src/**/*.js', 'test/**/*.js'],
      options: {
        jshintrc: '.jshintrc'
      }
    },

    jscs: {
      src: ['*.js', 'src/**/*.js', 'test/**/*.js'],
      options: {
        config: ".jscsrc"
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