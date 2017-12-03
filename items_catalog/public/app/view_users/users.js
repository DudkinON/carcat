(function () {
        // 'use strict';

        var users = angular.module('app.users', ['ngRoute']);
        users.config(['$routeProvider', function ($routeProvider) {
            $routeProvider.when('/login', {
                templateUrl: 'login.html',
                controller: 'LoginCtrl'
            });
        }]);
        users.controller('LoginCtrl', function ($resource) {
            this.email = '';
            this.password = '';
        });
})();
