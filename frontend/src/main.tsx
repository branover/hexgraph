import React from "react";
import ReactDOM from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import "./theme.css";
import Projects from "./pages/Projects";
import Workspace from "./pages/Workspace";
import Settings from "./pages/Settings";

const router = createBrowserRouter([
  { path: "/", element: <Projects /> },
  { path: "/projects/:projectId", element: <Workspace /> },
  { path: "/settings", element: <Settings /> },
]);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>
);
