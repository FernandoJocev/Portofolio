<?php

namespace App\Http\Controllers\Auth;

use App\Models\User;
use Illuminate\Support\Str;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Password;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Validation\Rules\Password as RulesPassword;

class ResetPasswordController extends Controller
{
    public function forgot(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
        ]);

        $status = Password::sendResetLink(
            $request->only('email'),
        );

        if ($status === Password::RESET_LINK_SENT) {
            return [
                'status' => __($status),
            ];
        }

        return response()->json([
            'message' => [trans($status)],
        ]);
    }

    public function reset(Request $request)
    // , $token
    {
        // if ($token === true)
        // {
        $userPass = User::first('password', $request->password);
        $password = Hash::check($request->password_confirmation, $userPass->password);
        // return response()->json([
        //     'message' => $password,
        // ]);
        if ($password === true)
        {
            $request->validate([
                'token' => 'required',
                'password' => ['required', 'confirmed', RulesPassword::defaults()]
            ]);
            return response()->json([
                'message' => 'Please enter a different password!',
            ]);
        }
        else {
            $request->validate([
            'token' => 'required',
            'password' => ['required', 'confirmed', RulesPassword::defaults()],
        ]);
        }
        
        $reset = Password::reset(
        $request->only('password', 'password_confirmation', 'token'), function ($user) use ($request) {
            $user->Fill([
                'password' => Hash::make($request->password),
                'remember_token' => Str::random(60),
            ])->update();

            event(new PasswordReset($user));
        }
    );

    if ($reset = Password::PASSWORD_RESET) {
        return response([
            'message' => 'Password has been reset!',
        ]);
    }

    return response([
        'message' => __($reset),
    ], 500);
// } else {
//     return response()->json([
//         'message' => 'Session expired!',
//     ]);
// };
   }
}