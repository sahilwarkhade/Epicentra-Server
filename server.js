import express from "express"
import mongoose from "mongoose";
import 'dotenv/config'
import bcrypt from 'bcrypt'
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken";
import cors from "cors"
import admin from "firebase-admin"
import serviceAccountKey from "./epicentra-blog-firebase-adminsdk-w64b1-4a68ab53b9.json" assert { type: 'json' };
import {getAuth} from "firebase-admin/auth"
import fileUplode from "express-fileupload"
import cloudinary from "./utils/cloudinary.js";



// schema 
import User from "./Schema/User.js"
import Blog from "./Schema/Blog.js"
import Notification from "./Schema/Notification.js"
import Comment from "./Schema/Comment.js"

import imageUploader from "./utils/imageUploader.js";
import uploadImageToCloudinary from "./utils/imageUploader.js";

const server=express();
server.use(express.json());
server.use(cors())
server.use(fileUplode({
    safeFileNames : true,
    preserveExtension: 10,
    useTempFiles: true,
    tempFileDir: "/tmp/"
}))

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

let PORT=3000;
let DB_URL=process.env.DB_LOCATION;

// google auth
admin.initializeApp({
    credential:admin.credential.cert(serviceAccountKey)
})

// connect to mongoDB
mongoose.connect(DB_URL,{
    autoIndex:true
}).then(()=>console.log("CONNECTED"));


// middleWare verifyJWT
const verifyJWT = (req,res,next) => {
    
    const authHeader=req.headers['authorization'];
    const token= authHeader && authHeader.split(" ")[1];
    
    if(!token){
        return res.status(401).json({
            error:"No access token"
        })
    }
    
    jwt.verify(token,process.env.SECRET_ACCESS_KEY,(err,user)=>{
        if(err){
            return res.status(403).json({
                error:"Access token is invalid"
            })
        }
        req.user=user.id;
        next();
    })
};

// formate data to be send
const formateDataToSend=(user)=>{

    const access_token=jwt.sign({id:user._id},process.env.SECRET_ACCESS_KEY)
    return{
        profile_img:user.personal_info.profile_img,
        username: user.personal_info.username,
        fullname:user.personal_info.fullname,
        access_token:access_token
    }
}

// generate username
const generateUsername=async(email)=>{

    let username = email.split('@')[0];

    let isUserNameNotUnique=await User.exists({"personal_info.username":username}).then((result)=>result)

    isUserNameNotUnique ? username+=nanoid(3) : "";

    return username;
}

// auth
// SIGN_UP
server.post("/signup",(req,res)=>{

    const {fullname,email,password}=req.body;

    if(fullname.length < 3){
        return res.status(403).json({
            "error":"FullName must be at least 3 letters long"
        })
    }

    if(!email.length){
        return res.status(403).json({
            "error":"Email Required"
        })
    }

    if(!emailRegex.test(email)){
        return res.status(403).json({
            "error":"Email is invalid"
        })
    }

    if(!passwordRegex.test(password)){
        return res.status(403).json({
            "error":"Password should be between 6 to 20 numeric , 1 lower case ,1 uppercase"
        })
    }


    bcrypt.hash(password,10,async (err,hashed_password)=>{

        let username=await generateUsername(email);

        let user=new User({
            personal_info:{
                fullname,
                email,
                password:hashed_password,
                username,
            }
        })

        user.save().then((u)=>{
            return res.status(200).json({
                success:true,
                user:formateDataToSend(u),
            })
        })
        .catch(err=>{

            if(err.code===11000){
                return res.status(500).json({
                    error:"Email already exist"
                })
            }
            return res.status(500).json({
                error:err.message
            })
        });
        // console.log(hashed_password);
    });
})

// SIGN_IN 
server.post("/signin",async(req,res)=>{
    const{email,password}=req.body;

    User.findOne({"personal_info.email":email}).then((user)=>{
        if(!user){
            return res.status(403).json({
                error:'Email not found',
            })
        }

        if(user.google_auth){
            return res.status(403).json({
                error:"Account is created with google try continue with google"
            })
        }

        bcrypt.compare(password,user.personal_info.password,(err,result)=>{
            if(err){
                return res.status(403).json({
                    error:'Something went wrong',
                })
            }
            if(!result){
                return res.status(403).json({
                    error:'Enter the correct password',
                })
            }
            else{
                return res.status(200).json({
                    success:true,
                    user:formateDataToSend(user)
                })
            }

        })

        // return res.status(403).json({success:true})
    }).catch(err=>{
        return res.status(500).json({
            error:err.message
        })
    })
})

// GOOGLE AUTH
server.post("/google-auth",async(req,res)=>{

    let access_token=req.body.access_token;
    // console.log("Asss "+access_token);
    // console.log("Req: ",req)
    getAuth().verifyIdToken(access_token).then(async(decodeUser)=>{
        let {email,name,picture}=decodeUser;

        picture = picture.replace("s96-c","s384-c");

        let user=await User.findOne({"personal_info.email":email}).select("personal_info.fullname personal_info.username personal_info.profile_img google_auth").then((u)=>{
            return u||null;
        })
        .catch(err=>{
            // console.log("1: ",err.message)
            return res.status(500).json({
                "error":err.message
            })
        });
        if(user){
            if(!user.google_auth){
                // console.log("0987654323456789")
                return res.status(403).json({
                    error:"This email is already register with email"
                })
            }
        }
        else{
            let username=await generateUsername(email)

            user=new User({
                personal_info:{fullname:name,username,email,profile_img:picture},
                google_auth:true
            })

            await user.save().then((u)=>{
                user=u
            })
            .catch(err=>{
                // console.log("3: ",err.message)
                return res.status(500).json({
                    error:err.message
                })
            })
        }

        return res.status(200).json({
            user:formateDataToSend(user)
        })
    })
    .catch(err=>{
        // console.log("2: ",err.message)
        return res.status(500).json({
            error:err.message
        })
    })
})

// change password
server.post("/change-password",verifyJWT,(req,res)=>{
    const user_id=req.user;

    let {currentPassword,newPassword}=req.body;

    if(!passwordRegex.test(newPassword) || !passwordRegex.test(currentPassword)){
        return res.status(403).json({error:"Enter Strong Password which contains 1 or more uppercase, lowercase character and Password must be between 6 to 20 character long"})
    }

    User.findOne({_id:user_id}).then((user)=>{
        if(user.google_auth){
            return res.status(403).json({
                error:"You can't change account password because you logged in with google account"
            })
        }

        bcrypt.compare(currentPassword,user.personal_info.password,(err,result)=>{
            if(err){
                return res.status(500).json({
                    error:"Something Went Wrong Please try again later"
                })
            }

            if(!result){
                return res.status(403).json({
                    error:"Incorrect current password"
                })
            }


            bcrypt.hash(newPassword,10,async(err,hashed_password)=>{
                await User.findOneAndUpdate({_id:user_id},{"personal_info.password":hashed_password}).then(doc=>{
                    return res.status(200).json({
                        Status:"Password change successfully"
                    })
                }).catch(err=>{
                    console.log("ERROR IN CHANGE PASSWORD 1",err)
                    return res.status(500).json({
                        error:"Something Went Wrong Please try again later"
                    })
                })
            })
        })
    }).catch(err=>{
        console.log("ERROR IN CHANGE PASSWORD 2",err)
        return res.status(500).json({
            error:"Something Went Wrong Please try again later"
        })
    })
})

// upload img to cloudinary
server.post("/uploadImage",async(req,res)=>{
    try {
        const img=req.files.image;
        console.log(img);
        const image=await uploadImageToCloudinary(img,process.env.FOLDER_NAME);
    
        if(image){
            return res.status(200).json({
                imageURL:image.secure_url
            })
        }
        else{
            return res.status(401).json({
                error:"Please try again image is not uploaded"
            })
        }
    } catch (error) {
        console.log(error)
        return res.status(500).json({
            error:"Something went wrong,Please Try Again"
        })
    }
})

////////////////////////// Blog Controllers///////////////////

// Create-blog
server.post("/create-blog",verifyJWT,(req,res)=>{
    const authorId=req.user;

    let{title,description,banner,tags,content,draft,id}=req.body;

    if(!title.length){
        return res.status(403).json({
            error:"You must provide a title to publish the blog"
        })
    }
    if(!draft){
        if(!banner.length){
            return res.status(403).json({
                error:"You must provide a blog banner to publish the blog"
            })
        }
        if(!content.blocks.length){
            return res.status(403).json({
                error:"You must provide a blog content to publish the blog"
            })
        }
        if(!description.length || description.length > 200){
            return res.status(403).json({
                error:"You must provide a description to publish the blog"
            })
        }
        if(!tags.length || tags.length > 10){
            return res.status(403).json({
                error:"You must provide a tags to publish the blog"
            })
        }
    }

    tags=tags.map(tag=>tag.toLowerCase());

    let blogId=id || title.replace(/[^a-zA-Z0-9]/g,' ').replace(/\s+/g,"-").trim()+nanoid();

    if(id){
        Blog.findOneAndUpdate({blog_id:blogId},{title,banner,des:description,content,tags,
        draft: draft ? draft : false}).
        then(blog=>{
            return res.status(200).json({id:blogId})
        })
        .catch(err=>{
            console.log("ERROR IN UPDATING BLOG WHILE CREATING BLOG:",err);
            return res.status(500).json({
                error:err.message
            })
        })
    }
    else{
        let blog=new Blog({
            title,banner,des:description,content,tags,author:authorId,blog_id:blogId,draft:Boolean(draft)
        })

        blog.save().then(blog=>{
            let incrementVal= draft ? 0 : 1;

            User.findOneAndUpdate({_id:authorId},
                { 
                    $inc:{"account_info.total_posts":incrementVal},
                    $push:{
                        "blogs":blog._id
                    }
                }
            ).then(user=>{
                return res.status(200).json({id:blog.blog_id})
            })
            .catch(err=>{
                return res.status(500).json({error:"falid to increment or push in blogs"})
            })
        }).catch(err=>{
            return res.status(500).json({error:err.message})
        })
    }
})

// Getting all Blogs
server.post('/latest-blogs',(req,res)=>{

    const {page}=req.body;
    let maxLimit=5;

    Blog.find({draft:false}).populate("author","personal_info.fullname personal_info.username personal_info.profile_img")
    .sort({"publishedAt":-1})
    .select("blog_id title des banner activity tags publishedAt")
    .skip((page-1)*maxLimit)
    .limit(maxLimit)
    .then(blogs=>{
        return res.status(200).json({blogs})
    })
    .catch(err=>{
        console.log("ERR in fetching Blog :",err.message)
        return res.status(500).json({
            error:"Error in fetching blogs"
        })
    })
})

// getting all latest blog count
server.post("/all-latest-blogs-count",(req,res)=>{
    Blog.countDocuments({draft:false}).then(count=>{
        return res.status(200).json({totalDocs:count})
    })
    .catch(err=>{
        console.log("IN GETTING ALL LATEST BLOG COUNT :",err.message)
        return res.status(500).json({
            error:err.message
        })
    })
})


// getting trending Blogs
server.get('/trending-blogs',(req,res)=>{
    Blog.find({draft:false}).populate("author","personal_info.fullname personal_info.username personal_info.profile_img")
    .sort({"activity.total_reads":-1,"activity.total_likes":-1,"publishedAt":-1})
    .select("blog_id title publishedAt")
    .limit(5)
    .then((blogs=>{
        return res.status(200).json({
            blogs
        })
    }))
    .catch(err=>{
        return res.status(500).json({
            error:"ERROR in fetching trending blogs"
        })
    })
})

// getting Blog using categories
server.post("/search-blogs",(req,res)=>{
    let {tag,query,page,author,limit,eliminate_blog}=req.body;

    let findQuery;

    if(tag){
        findQuery={tags:tag,draft:false,blog_id:{$ne:eliminate_blog}};
    }
    else if(query){
        findQuery={draft:false,title:new RegExp(query,"i")}
    }
    else if(author){
        findQuery={author,draft:false}
    }

    let maxLimit=limit ? limit : 2;

    Blog.find(findQuery)
    .populate("author","personal_info.fullname personal_info.username personal_info.profile_img")
    .sort({"publishedAt":-1})
    .select("blog_id title des banner activity tags publishedAt")
    .skip((page-1)*maxLimit)
    .limit(maxLimit)
    .then(blogs=>{
        return res.status(200).json({blogs})
    })
    .catch(err=>{
        console.log("ERR in fetching Blog :",err)
        return res.status(500).json({
            error:"Error in Categories blogs"
        })
    })
})

// 
server.post("/search-blogs-count",(req,res)=>{
    let {tag,query,author}=req.body;

    let findQuery;

    if(tag){
        findQuery={tags:tag,draft:false};
    }
    else if(query){
        findQuery={draft:false,title:new RegExp(query,"i")}
    }
    else if(author){
        findQuery={author,draft:false}
    }

    Blog.countDocuments(findQuery).then(count=>{
        return res.status(200).json({
            totalDocs:count
        })
    }).catch(err=>{
        console.log("ERROR IN GETTING SEARCH BLOGS :",err.message);
        return res.status(500).json({
            error:err.message
        })
    })
})

// searching user
server.post('/search-users',(req,res)=>{
    const {query}=req.body;

    User.find({"personal_info.username":new RegExp(query,"i")})
    .limit(50)
    .select("personal_info.username personal_info.fullname personal_info.profile_img")
    .then((users)=>{ 
        return res.status(200).json({users})
    })
    .catch(err=>{
        console.log("ERROR IN SEACHING USER :",err);
        return res.status(500).json({
            error:err.message
        })
    })
})

// searching specifiic profile
server.post("/get-profile",(req,res)=>{
    let {username}=req.body;

    User.findOne({"personal_info.username":username})
    .select("-personal_info.password -google_auth -updatedAt -blogs")
    .then((user)=>{
        return res.status(200).json(user)
    })
    .catch(err=>{
        console.log("ERROR IN SEARCHING SPECIFIC USER");
        return res.status(500).json({
            error:err.message
        })
    })
})

// update profile image;
server.post("/update-profile-image",verifyJWT,(req,res)=>{
    let {url}=req.body;

    const user_id=req.user;

    User.findOneAndUpdate({_id:user_id},{"personal_info.profile_img":url}).then(()=>{
        return res.status(200).json({profile_img:url});
    }).catch(err=>{
        console.log("ERROR IN UPDATING PROFILE IMAGE:::",err);
        return res.status(500).json({
            error:"Something went wrong"
        })
    })
})

// update profile details
server.post("/update-profile",verifyJWT,(req,res)=>{

    const user_id=req.user;
    let{username,bio,social_links}=req.body;


    let social_links_array=Object.keys(social_links);

    try{

        for(let i=0; i < social_links_array.length; i++){
            if(social_links[social_links_array[i]].length){
                let hostname= new URL(social_links[social_links_array[i]]).hostname;

                if(!hostname.includes(`${social_links_array[i]}.com`) && social_links_array[i] !="website"){
                    return res.status(403).json({
                        "error":`${social_links_array[i]} link is invalid enter valid url`
                    })
                }
            }
        }

    }catch(err){
        return res.status(500).json({
            "error":"you must provide a valid url"
        })
    }

    let updateObj={
        "personal_info.username":username,
        "personal_info.bio":bio,
        social_links
    }

    User.findOneAndUpdate({_id:user_id},updateObj,{
        runValidators:true
    })
    .then(()=>{
        return res.status(200).json({
            username
        })
    })
    .catch(err=>{
        console.log("ERROR IN UPDATING PROFILE DETAILS::",err);
        if(err.code==11000){
            return res.status(409).json({
                "error":"Username is already taken"
            })
        }

        return res.status(500).json({
            "error":"Something went wrong"
        })
    })
})

// getting BLOG USING BLOG_ID
server.post("/get-blog",(req,res)=>{
    const {blog_id,draft,mode}=req.body;

    let incrementVal=mode != "edit" ? 1 : 0;

    Blog.findOneAndUpdate({blog_id},{$inc:{"activity.total_reads":incrementVal}},{new:true}).populate("author","personal_info.username personal_info.fullname personal_info.profile_img").select("title des content banner activity publishedAt bllog_id tags").then(blog=>{
        User.findOneAndUpdate({"personal_info.username":blog.author.personal_info.username},{$inc:{"account_info.total_reads":incrementVal}}).catch(err=>{
            console.log("ERROR IN FINDING USER IN BLOG_ID:",err);
            return res.status(500).json({
                error:"Something went wrong"
            })
        })

        if(blog.draft && !draft){
            return res.status(500).json({error:"You can access the blog"})
        }

        return res.status(200).json({blog})
    })
    .catch(err=>{
        console.log("ERROR IN GETTING BLOG BY ID: ",err);
        return res.status(500).json({
            error:"Something went wrong"
        })
    })
})

// LIKE THE BLOG
server.post("/like-blog",verifyJWT,(req,res)=>{
    const user_id=req.user;

    const { _id, isLikedByUser }=req.body;

    let incrementVal=!isLikedByUser ? 1 : -1;

    Blog.findOneAndUpdate({_id},{$inc:{"activity.total_likes":incrementVal}}).then((blog)=>{
        if(!isLikedByUser){
            let like=new Notification({
                type:"like",
                blog:_id,
                notification_for:blog.author,
                user:user_id
            })

            like.save().then(notification=>{
                return res.status(200).json({liked_by_user:true})
            })
            .catch(err=>{
                console.log("ERROR IN LIKE BLOG");
                return res.status(500).json({
                    error:err.message
                })
            })
        }
        else{
            Notification.findOneAndDelete({user:user_id,type:"like",blog:_id}).then(data=>{
                return res.status(200).json({liked_by_user:false})
            }).catch(err=>{
                console.log("ERROR IN LIKE BLOG");
                return res.status(500).json({
                    error:err.message
                })
            })
        }
    })
})

// GIVES LIKE COUNT
server.post("/isLiked-by-user",verifyJWT,(req,res)=>{
    let user_id=req.user;

    let {_id}=req.body;
    
    Notification.exists({user:user_id,type:"like",blog:_id}).then(result=>{
        return res.status(200).json({result})
    }).catch(err=>{
        console.log("GIVES LIKE COUNT",err);
        return res.status(500).json({
            error:err.message
        })
    })
})

// creating comment
server.post("/add-comment",verifyJWT,(req,res)=>{
    const user_id=req.user;

    let{_id,comment,blog_author}=req.body;

    if(!comment.length){
        return res.status(403).json({
            error:"Write something to leave a comment"
        })
    }

    // creating a comment'
    let commentObj=new Comment({
        blog_id:_id,blog_author,comment,commented_by:user_id
    })

    commentObj.save().then(commentFile=>{
        let {comment,commentedAt,children} =commentFile;
        Blog.findOneAndUpdate({_id},{$push:{"comments":commentFile._id},$inc:{"activity.total_comments":1},"activity.total_parent_comments":1}).then(blog=>{
            // console.log(blog)
        })
        let notificationObj=new Notification({
            type:"comment",
            blog:_id,
            notification_for:blog_author,
            user:user_id,
            comment:commentFile._id
        })
        notificationObj.save().then(not=>{
            console.log(not);
        })

        return res.status(200).json({
            comment,commentedAt,_id:commentFile._id,user_id,children
        })
    })

})

// get Blog comment
server.post("/get-blog-comments",(req,res)=>{
    let{blog_id,skip}=req.body;

    let maxLimit=5;

    Comment.find({blog_id,isReply:false}).populate("commented_by","personal_info.username personal_info.fullname personal_info.profile_img").skip(skip).limit(maxLimit).sort({"commentedAt":-1}).then((comment)=>{
        return res.status(200).json(comment)
    }).catch(err=>{
        console.log("ERROR IN GETTING COMMENT");
        return res.status(500).json({
            error:err.message
        })
    })
})

// delete the comment
server.post("/delete-comment",verifyJWT,(req,res)=>{
    const user_id=req.user;

    let{_id}=req.body;

    Comment.findOne({_id}).then(comment=>{
        if(user_id == comment.commented_by){
            
            Comment.findOneAndDelete({_id}).then(comment=>{
                Notification.findOneAndDelete({comment:_id}).then().catch(err=>{
                    console.log("ERROR WHILE DELETING COMMENT IN NOTIFICATION",err);
                    return res.status(500).json({
                        error:"Somthing went wrong"
                    })
                })

                Blog.findOneAndUpdate({_id:comment.blog_id},{$pull:{comments:_id},$inc:{
                    "activity.total_comments":-1,
                    "activity.total_parent_comments":-1
                }
                }).then().catch(err=>{
                    console.log("ERROR WHILE DELETING COMMENT IN BLOG",err);
                    return res.status(500).json({
                        error:"Somthing went wrong"
                    })
            })

            return res.status(200).json({Status:"done"})
            })
            .catch(err=>{
                console.log("ERROR WHILE DELETING COMMENT");
                return res.status(500).json({
                    error:"Somthing went wrong"
                })
            })
        }
        else{
            return res.status(403).json({error:"You can not delete the comment"})
        }
    })
})

/////////////////////NOTIFICATIONS////////////////////////
// getting notification alert
server.get("/new-notification",verifyJWT,(req,res)=>{
    const user_id=req.user;
    

    Notification.exists({notification_for:user_id,seen:false,user:{$ne:user_id}}).then(result=>{
        if(result){
            return res.status(200).json({
                new_notification_available:true
            })
        }else{
            return res.status(200).json({
                new_notification_available:false
            })
        }
    }).catch(err=>{
        console.log("ERROR IN GETTING NOTIFICATION:::",err);

        return res.status(500).json({
            error:"something went wrong"
        })
    })
})
server.post("/notifications",verifyJWT,(req,res)=>{
    const user_id=req.user;

    let {page,filter,deletedDocCount}=req.body;

    let maxLimit=5;

    let findQuery={notification_for:user_id,user:{$ne:user_id}};

    let skipDocs=(page-1)*maxLimit

    if(filter != 'all'){
        findQuery.type=filter;
    }
    if(deletedDocCount){
        skipDocs-=deletedDocCount;
    }

    Notification.find(findQuery).skip(skipDocs).limit(maxLimit).populate("blog","title blog_id").populate("user",'personal_info.fullname personal_info.username personal_info.profile_img').populate("comment","comment").sort({createdAt:-1}).select("createdAt type seen").then((notifications)=>{

        Notification.updateMany(findQuery,{seen :true}).skip(skipDocs).limit(maxLimit).then();
        return res.status(200).json({notifications})
    }).catch(err=>{
        console.log("ERROR IN NOTIFIACTION:::",err);

        return res.status(500).json({
            error:"something went wrong"
        })
    })
})

// GETTING ALL NOTIFICATION COUNT

server.post("/all-notification-count",verifyJWT,(req,res)=>{
    const user_id=req.user;

    let {filter}=req.body;

    let findQuery={notification_for:user_id,user:{$ne:user_id}}

    if(filter!="all"){
        findQuery.type=filter;
    }

    Notification.countDocuments(findQuery).then((count)=>{
        return res.status(200).json({totalDocs:count})
    }).catch(err=>{
        console.log("ERROR IN NOTIFIACTION COUNT:::",err);

        return res.status(500).json({
            error:"something went wrong"
        })
    })
})

// GETTING USER WRITEEN BLOGS
server.post("/user-written-blogs",verifyJWT,(req,res)=>{
    const user_id=req.user;

    let {page,draft,query,deletedDocCount}=req.body;

    let maxLimit=5;
    let skipDocs=(page-1)*maxLimit;

    if(deletedDocCount){
        skip-=deletedDocCount;
    }

    Blog.find({author:user_id,draft,title: new RegExp(query,'i')}).skip(skipDocs).limit(maxLimit).sort({publishedAt:-1}).select("title banner publishedAt blog_id activity des draft").then(blogs=>{
        return res.status(200).json({
            blogs
        })
    }).catch(err=>{
        console.log("ERROR IN GETTING BLOGS:::",err);
        return res.status(500).json({
            error:"Something went wrong"
        })
    })
})

// GETTING COUNT OF BLOGS OF USER
server.post("/user-written-blogs-count",verifyJWT,(req,res)=>{
    const user_id=req.user;

    let {draft,query}=req.body;

    Blog.countDocuments({author:user_id,draft,title:new RegExp(query,'i')}).then(count=>{
        return res.status(200).json({
            totalDocs:count
        });
    }).catch(err=>{
        console.log("ERROR IN COUNTING THE USER BLOGS:::",err);
        return res.status(500).json({
            error:"Something went wrong"
        });
    })

})

// DELETE BLOG 
server.post("/delete-blog",verifyJWT,(req,res)=>{
    const user_id=req.user;
    let {blog_id}=req.body;


    Blog.findOneAndDelete({blog_id}).then(blog=>{
        Notification.deleteMany({blog:blog._id}).then().catch(err=>{
            console.log("ERROR IN DELETING BLOG WHILE DELETHING NOTIFICATION:::",err)
            return res.status(500).json({
                error:"Something went wrong"
            })
        })
        Comment.deleteMany({blog_id:blog._id}).then().catch(err=>{
            console.log("ERROR IN DELETING BLOG WHILE DELETHING Comment:::",err)
            return res.status(500).json({
                error:"Something went wrong"
            })
        })

        User.findOneAndUpdate({_id:user_id},{$pull:{blog:blog._id},$inc:{"account_info.total_posts":-1}}).then()
        .catch(err=>{
            console.log("ERROR IN DELETING BLOG WHILE DELETHING User:::",err)
            return res.status(500).json({
                error:"Something went wrong"
            })
        })
        return res.status(200).json({status:"done"})
    }).catch(err=>{
        console.log("ERROR IN DELETING BLOG:::",err)
        return res.status(500).json({
            error:"Something went wrong"
        })
    })
})


server.listen(PORT,(req,res)=>{
    console.log("Listening on port:"+PORT)
})