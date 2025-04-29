package main

import (
   "bufio"
   "fmt"
   "io"
   "net"
   "github.com/gdamore/tcell/v2"
   "github.com/rivo/tview"
)

// RunChatUI launches a text-based chat interface over the given connection.
// RunChatUI launches a text-based chat interface over the given connection,
// displaying the pairing code in the left pane.
func RunChatUI(conn net.Conn, code string) {
	// Set background color to dracula theme (#282a36)
	bgColor := tcell.NewRGBColor(40, 42, 54)
	app := tview.NewApplication()

   // Create the main layout
   flex := tview.NewFlex().SetDirection(tview.FlexRow)
   flex.SetBackgroundColor(bgColor)

   // Create the title
   title := tview.NewTextView().
       SetTextAlign(tview.AlignCenter).
       SetText("airsend -by 4rji")
   title.SetBackgroundColor(bgColor)
   title.SetTextColor(tcell.ColorAqua)

   // Create the chat area
   chatArea := tview.NewTextView().
       SetDynamicColors(true).
       SetChangedFunc(func() {
           app.Draw()
       })
   chatArea.SetBackgroundColor(bgColor)
   chatArea.SetBorder(true)
   chatArea.SetTitle("Chat")
   chatArea.SetTitleColor(tcell.ColorAqua)

   // Create the code display pane
   codeView := tview.NewTextView().
       SetTextAlign(tview.AlignCenter).
       SetText(code)
   codeView.SetBackgroundColor(bgColor)
   codeView.SetBorder(true)
   codeView.SetTitle("Code")
   codeView.SetTitleColor(tcell.ColorAqua)

   // Create the input field
   input := tview.NewInputField().
       SetLabel("> ").
       SetFieldWidth(0)
   input.SetBackgroundColor(bgColor)
   input.SetFieldBackgroundColor(bgColor)
   input.SetBorder(true)

    // Prepare writer to send messages to peer
    writer := bufio.NewWriter(conn)
    // Handle input: send messages over the connection and display in chat area.
    input.SetDoneFunc(func(key tcell.Key) {
        if key == tcell.KeyEnter {
            text := input.GetText()
            if text != "" {
                // Send to peer
                if _, err := writer.WriteString(text + "\n"); err != nil {
                    chatArea.Write([]byte(fmt.Sprintf("[red]Error sending: %v\n", err)))
                } else {
                    writer.Flush()
                }
                // Display locally
                chatArea.Write([]byte("You: " + text + "\n"))
                input.SetText("")
            }
        }
    })

    // Start network reader: receive messages from connection and display.
    go func() {
        reader := bufio.NewReader(conn)
        for {
            line, err := reader.ReadString('\n')
            if err != nil {
                if err != io.EOF {
                    chatArea.Write([]byte(fmt.Sprintf("[red]Error reading: %v\n", err)))
                }
                return
            }
            chatArea.Write([]byte("Peer: " + line))
        }
    }()

    // Layout setup
   mainFlex := tview.NewFlex().
       AddItem(codeView, 20, 1, false).
       AddItem(chatArea, 0, 1, false)
   mainFlex.SetBackgroundColor(bgColor)

	flex.AddItem(title, 1, 1, false).
		AddItem(mainFlex, 0, 1, false).
		AddItem(input, 3, 1, true)

	// Set up colors and borders
	flex.SetBorderColor(tcell.ColorAqua)
	flex.SetBorder(true)

   // Run the application (blocks until exit).
   // Disable mouse capture so terminal selection can work for copy/paste.
   if err := app.SetRoot(flex, true).Run(); err != nil {
       panic(err)
   }
}
