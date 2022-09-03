<?php

namespace App\Http\Controllers\Auth;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Auth;
use Tymon\JWTAuth\Facades\JWTFactory;

class AuthController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    /**
     * Login.
     *
     * @return \Illuminate\Http\Response
     */
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            "username" => "required|min:3",
            "email" => "required|email",
            "password" => "required|string|min:8",
        ]);
        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }
        if (! $token = auth()->attempt($validator->validated())) {
            return response()->json(['error' => "Unauthorized"], 401);
        };

        return $this->createNewToken($token);
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            "username" => "required|alpha_dash|unique:users,username|min:3",
            "name" => "required|min:3|unique:users,name",
            "email" => "required|unique:users,email",
            "password" => "required|min:8",
        ]);

        if ($validator->fails())
        {
            return response()->json($validator->errors(), 400);
        };

        $user = User::create(array_merge(
            $validator->validated(),
            ["password" => bcrypt($request->password)],
        ));

        return response()->json([
            "message" => "Register sukes",
            "user" => $user,
        ], 201);
    }

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function userProfile()
    {
        return response()->json(auth()->guard('api')->user());
    }

    // public function refresh()
    // {
    //     return $this->createNewToken(auth()->guard('api')->refresh());
    // }

    /**
     * Logout.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function logout()
    {
        auth()->guard('api')->logout();

        return response()->json([
            "message" => "Berhasil logout",
        ]);
    }

    /**
     * Generate Auth Token
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    protected function createNewToken($token)
    {
        // $encode = JWTAuth::encode($token);
        return response()->json([
            'token' => $token,
        ]);
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function destroy()
    {

    }
}