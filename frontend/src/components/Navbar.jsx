import React from "react";
import { NavLink } from "react-router-dom";
import Logout from "./Logout";
import { useAuthContext } from "../context/AuthContext";
const Navbar = () => {
  const { authUser } = useAuthContext();

  return (
    <div className="flex items-center justify-between w-full px-4 py-2  text-white bg-[#24292F] rounded-md">
      <h1 className="text-xl sm:text-lg font-bold bg-gradient-to-r from-purple-400 to-red-500 text-transparent bg-clip-text ">
        Precogs.AI
      </h1>
      <div className="flex gap-4 sm:gap-3">
        <NavLink
          to="/"
          className=" hover:text-lime-400"
          style={({ isActive }) => (isActive ? { color: "#4feb34" } : null)}
        >
          Home
        </NavLink>
        {authUser ? (
          <>
            <NavLink
              to="/profile"
              className=" hover:text-lime-400"
              style={({ isActive }) => (isActive ? { color: "#4feb34" } : null)}
            >
              Profile
            </NavLink>
            <Logout />
          </>
        ) : (
          <>
            <NavLink
              to="/signup"
              className=" hover:text-lime-400"
              style={({ isActive }) => (isActive ? { color: "#4feb34" } : null)}
            >
              Signup
            </NavLink>
            <NavLink
              to="/login"
              className=" hover:text-lime-400"
              style={({ isActive }) => (isActive ? { color: "#4feb34" } : null)}
            >
              Login
            </NavLink>
          </>
        )}
      </div>
    </div>
  );
};

export default Navbar;
