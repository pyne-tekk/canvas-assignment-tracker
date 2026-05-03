import "@/App.css";

function App() {
  return (
    <div
      className="App"
      style={{
        position: "fixed",
        inset: 0,
        margin: 0,
        padding: 0,
        background: "#05070d",
        overflow: "hidden",
      }}
    >
      <iframe
        title="Slate"
        src="/slate.html"
        data-testid="slate-frame"
        style={{
          width: "100%",
          height: "100%",
          border: 0,
          display: "block",
        }}
      />
    </div>
  );
}

export default App;
