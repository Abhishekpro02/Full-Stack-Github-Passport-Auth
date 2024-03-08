import { Navigate, Route, Routes } from "react-router-dom";
import Home from "./components/Home";
import SignUpPage from "./pages/SignUp";
import LoginPage from "./pages/Login";
import Navbar from "./components/Navbar";
import Profile from "./pages/Profile";
import { useAuthContext } from "./context/AuthContext";

const App = () => {
  const { authUser, loading } = useAuthContext();
  console.log("App -> authUser", authUser);
  console.log("loading", loading);
  return (
    <div className="flex">
      <div className="max-w-5xl my-5 text-white mx-auto transition-all duration-300 flex-1">
        <Navbar />
        <Routes>
          <Route path="/" element={<Home />} />
          <Route
            path="/login"
            element={!authUser ? <LoginPage /> : <Navigate to={"/"} />}
          />
          <Route
            path="/signup"
            element={!authUser ? <SignUpPage /> : <Navigate to={"/"} />}
          />
          <Route
            path="/profile"
            element={authUser ? <Profile /> : <Navigate to={"/"} />}
          />
        </Routes>
      </div>
    </div>
  );
};

export default App;
