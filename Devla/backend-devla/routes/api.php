<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Auth\AuthController;
use App\Http\Controllers\Auth\ResetPasswordController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

// Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
//     return $request->user();
// });

Route::group([
    "middleware" => "api",
    "prefix" => "auth",
], function ($router) {
    Route::post('login', [AuthController::class, 'login']);
    Route::post('forget-password', [ResetPasswordController::class, 'forgot']);
    Route::post('resend', [ResetPasswordController::class, 'forgot']);
    // /{token}
    Route::post('reset-password', [ResetPasswordController::class, 'reset']);
    Route::post('register', [AuthController::class, 'register']);
    Route::post('profile', [AuthController::class, 'userProfile']);
    // Route::post('refresh', [AuthController::class, 'refresh']);
    Route::post('logout', [AuthController::class, 'logout']);
});