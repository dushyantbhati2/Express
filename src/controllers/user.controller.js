import { asyncHandler } from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js"
import {User} from "../models/user.models.js"
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken"

const generateAccessAndRefereshToken=async(userId)=>{
    try {
        const user=await User.findById(userId)
        const accessToken=user.generateAccessToken()
        const refreshToken=user.generateRefreshToken()
        user.refreshToken=refreshToken
        await user.save({ validateBeforeSave:false })

        return {accessToken,refreshToken}
    } catch (error) {
        throw new ApiError(500,"Something went wrong while generating Access and Referesh Token")
    }
}

const registerUser=asyncHandler( async (req,res) =>{
    // get user details from frontend
    // validation - not empty
    // check if user already exists : username,email
    // check for images
    // check for avatar
    // upload them to cloundinary, avatar
    // create user object - create entry in db
    // remove password and refresh token from Response
    // check for usercreation
    // return response

    console.log(req.body);
    const {fullName,email,username,password}=req.body
    if (
        [fullName,email,username,password].some((field) => field?.trim() === "")
    ) {
        throw new ApiError(400,"All fields are required")
    }
    
    const existedUser= await User.findOne({
        $or:[{username},{email}]
    })
    
    if(existedUser){
        throw new ApiError(409,"User with email or username already exists")
    }
    
    const avatarLocalPath=req.files?.avatar[0]?.path
    // const coverImageLocalPath=req.files?.coverImage[0]?.path
    // console.log(req.files);
    
    if(!avatarLocalPath){
        throw new ApiError(400,"Avatar is required")
    }
    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files?.coverImage[0]?.path
    }
    const avatar=await uploadOnCloudinary(avatarLocalPath)
    const coverImage=await uploadOnCloudinary(coverImageLocalPath)
    if(!avatar){
        throw new ApiError(400,"Avatar file is required")
    }
    
    const user= await User.create({
        fullname:fullName,
        avatar:avatar.url,
        coverImage:coverImage?.url || "",
        email,
        password,
        username:username.toLowerCase()
        
    })
    
    const createdUser=await User.findById(user._id).select(
        "-password -refreshToken"
    )
    if(!createdUser){
        throw new ApiError(500,"Something went wrong while registering the user")
    }
    // console.log(createdUser)
    return res.status(201).json(
        new ApiResponse(200,createdUser,"User Sucessfully Registered")
    )
})

const loginUser=asyncHandler(async (req,res)=>{
    // req body -> data
    // username or email
    // find the user
    // password check
    // access and refresh token
    // send cookie
    console.log(req.body);
    const {email,username,password}=req.body

    if(!username && !email){
        throw new ApiError(400,"username or email is required")
    }

    const user=await User.findOne({
        $or:[{username},{email}]
    })

    if(!user){
        throw new ApiError(404,"User doesn't exists")
    }

    const isPasswordValid=await user.isPasswordCorrect(password)

    if(!isPasswordValid){
        throw new ApiError(401,"Invalid user credentials")
    }

    const {accessToken,refreshToken}=await generateAccessAndRefereshToken(user._id)

    const loggedInUser=await User.findById(user._id).select(["-password -refreshToken"])
    const options = {
        httpOnly: true,
        secure: true
    }

    return res.status(200)
    .cookie("accessToken",accessToken,options)
    .cookie("refreshToken",refreshToken,options)
    .json(
        new ApiResponse(
            201,
            {
                user:loggedInUser,
                accessToken,
                refreshToken
            },
            "User logged In successfully"
        )
    )
})

const logoutUser=asyncHandler(async(req,res)=>{
    console.log("YES");
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set:{
                refreshToken:undefined
            }
        },
        {
            new:true
        }
    )
    const options = {
        httpOnly: true,
        secure: true
    }
    return res
    .status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken",options)
    .json( new ApiResponse(200,{},"User Logged Out"))

})
const refreshAccessToken=asyncHandler(async(req,res)=>{
    const incomingRefreshToken=req.cookies.refreshToken || req.body.refreshToken
    if(!incomingRefreshToken){
        throw new ApiError(401,"Unauthorized request")
    }

    try {
        const decodedToken=jwt.verify(incomingRefreshToken,process.env.REFRESH_TOKEN_SECRET)
        const user=await User.findById(decodedToken?._id)
    
        if(!user){
            throw new ApiError(400,"Invalid Refresh Token")
        }
    
        if(user?.refreshToken !== decodedToken ){
            throw new ApiError(400,"Refresh Token is used or expired")
        }
    
        const options={
            httpOnly:true,
            secure:true
        }
    
        const {accessToken,newRefreshToken}=await generateAccessAndRefereshToken(user._id)
    
        return res
        .status(200)
        .cookie("accessToken",accessToken,options)
        .cookie("refreshToken",newRefreshToken,options)
        .json(
            new ApiResponse(200,
                {accessToken,refreshToken:newRefreshToken},
                "Access Token refreshed"
            )
        )
    } catch (error) {
        throw new ApiError(400,error?.message || "Invalid refresh token")
    }


})
export {registerUser , loginUser,logoutUser , refreshAccessToken}