import React from "react";

const Home = () => {
  return (
    <div className="flex min-h-screen justify-center items-center flex-col">
      <h1
        className="text-4xl font-bold text-center text-white mb-4"
        style={{ textShadow: "0 0 10px rgba(0,0,0,0.5)" }}
      >
        Github Auth with Passport.js
      </h1>
      <p
        className="mt-4 text-gray-500
        text-center w-96 sm:w-auto lg:w-1/2 xl:w-1/3  text-lg font-semibold
      "
      >
        This is a simple app that demonstrates how to authenticate users using
        Github OAuth with Passport.js.
      </p>
    </div>
  );
};

export default Home;
