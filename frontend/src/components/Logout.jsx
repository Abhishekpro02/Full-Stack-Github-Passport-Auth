import { MdLogout } from "react-icons/md";
import { useAuthContext } from "../context/AuthContext";
import { toast } from "react-hot-toast";
import { useNavigate } from "react-router-dom";
import { BASE_URL } from "../utils/constant";
// TODO Implement Logout functionality

const Logout = () => {
  const { authUser, setAuthUser } = useAuthContext();
  const navigate = useNavigate();

  const handleLogout = async () => {
    try {
      const res = await fetch(`/api/auth/logout`, {
        credentials: "include",
      });
      const data = await res.json();
      console.log(data);
      setAuthUser(null);
      navigate("/login");
    } catch (error) {
      toast.error(error.message);
    }
  };

  return (
    <>
      {/* <img
        src={authUser?.avatarUrl}
        className="w-10 h-10 rounded-full border border-gray-800"
      /> */}

      <div
        className="cursor-pointer  border border-gray-800"
        onClick={handleLogout}
      >
        <MdLogout size={22} />
      </div>
    </>
  );
};

export default Logout;
