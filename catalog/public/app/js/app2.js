'use strict';

var app = angular.module('app', []);
app.controller('Controller', ['$scope', function($scope) {
        $scope.customer = {
            name: 'Naomi',
            address: '1600 Amphitheatre'
        };
    }]);
app.directive('myCustomer', function() {
        return function (scope, element, attrs) {

        }
    });