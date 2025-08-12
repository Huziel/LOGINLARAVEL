<?php

namespace App\Http\Controllers;

use App\Http\Requests\UserRegistrationRequest;
use App\User;
use App\UserRole;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;

class AuthController extends Controller
{
    /**
     * register user
     *
     * @return [json] user object
     */
    public function register(UserRegistrationRequest $request)
    {
        try {
            DB::beginTransaction();

            $input = $request->all();
            $input['password'] = Hash::make($input['password']);

            $user = User::create($input);

            $user->assignRole(UserRole::where('name', 'user')->first());

            $token = $user->createToken('authToken')->accessToken;

            $message = 'User created successfully';
            $http_code = HTTP_CREATED;

            DB::commit();

            return $this->apiResponse($message, $user, $token, $http_code);
        } catch (\Exception $e) {
            DB::rollBack();
            Log::error($e->getMessage());

            $message = 'An error occurred when trying to register a user.';
            $http_code = HTTP_INTERNAL_SERVER_ERROR;

            return $this->apiResponse($message, null, null, $http_code);
        }
    }

    /**
     * @return [json] object
     */
    public function login(Request $request)
    {
        $credentials = [
            'email' => $request->email,
            'password' => $request->password
        ];

        if (!auth()->attempt($credentials)) {
            $message = 'Invalid credentials. Please try again.';
            $http_code = HTTP_UNAUTHORIZED;

            return $this->apiResponse($message, null, null, $http_code);
        }

        $user = auth()->user();

        $token = $user->createToken('authToken')->accessToken;
        $message = 'User logged in successfully.';
        $http_code = HTTP_OK;

        return $this->apiResponse($message, $user, $token, $http_code);
    }


    /**
     * logout user
     *
     * @return [json] success message
     */
    public function logout(Request $request)
    {
        try {
            $user = auth()->user();
            $token = $user->token();

            $token->revoke();

            $message = 'User logged out successfully.';
            $http_code = HTTP_OK;

            return $this->apiResponse($message, null, null, $http_code);
        } catch (\Exception $e) {
            Log::error($e->getMessage());

            $message = 'An error occurred when trying to log out a user.';
            $http_code = HTTP_INTERNAL_SERVER_ERROR;

            return $this->apiResponse($message, null, null, $http_code);
        }
    }

    /**
     * @return [json] user object
     */
    public function update_profile(UserRegistrationRequest $request)
    {
        try {
            DB::beginTransaction();

            $user = auth()->user();
            $user->update($request->all());

            $message = 'User profile updated successfully.';
            $http_code = HTTP_OK;

            DB::commit();

            return $this->apiResponse($message, $user, null, $http_code);
        } catch (\Exception $e) {
            DB::rollBack();
            Log::error($e->getMessage());

            $message = 'An error occurred when trying to update the user profile.';
            $http_code = HTTP_INTERNAL_SERVER_ERROR;

            return $this->apiResponse($message, null, null, $http_code);
        }
    }

    /**
     * @return [json] user object
     */
    public function delete_user(Request $request)
    {
        try {
            $user = auth()->user();
            $user->delete();

            $message = 'User deleted successfully.';
            $http_code = HTTP_OK;

            return $this->apiResponse($message, null, null, $http_code);
        } catch (\Exception $e) {
            Log::error($e->getMessage());

            $message = 'An error occurred when trying to delete the user.';
            $http_code = HTTP_INTERNAL_SERVER_ERROR;

            return $this->apiResponse($message, null, null, $http_code);
        }
    }
}