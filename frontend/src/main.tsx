import React from "react";
import ReactDOM from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import "./theme.css";
import Projects from "./pages/Projects";
import Workspace from "./pages/Workspace";

const router = createBrowserRouter([
  { path: "/", element: <Projects /> },
  { path: "/projects/:projectId", element: <Workspace /> },
]);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>
);
