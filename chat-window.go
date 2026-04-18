package main

import (
	"bufio"
	"fmt"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"io"
	"net"
)

// RunChatUI launches a text-based chat interface over the given connection.
// RunChatUI launches a text-based chat interface over the given connection,
// displaying the pairing code in the left pane.
func RunChatUI(conn net.Conn, code string) {
	// Cyberpunk palette — matches cyberpunk-website/index.html
	// bg #05020f, purple #a855f7, fuchsia #d946ef, cyan #22d3ee
	bgColor := tcell.NewRGBColor(5, 2, 15)
	borderColor := tcell.NewRGBColor(168, 85, 247)  // --purple
	accentColor := tcell.NewRGBColor(34, 211, 238)  // --cyan
	app := tview.NewApplication()

	// Create the main layout
	flex := tview.NewFlex().SetDirection(tview.FlexRow)
	flex.SetBackgroundColor(bgColor)

	// Create the title
	title := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter).
		SetText("[#d946ef::b]airsend[-:-:-]  [#6b6494]PgUp/PgDn scroll · End jump · Ctrl+C quit[-]")
	title.SetBackgroundColor(bgColor)

	// Create the chat area
	chatArea := tview.NewTextView().
		SetDynamicColors(true)
	chatArea.SetScrollable(true).SetWrap(true)
	chatArea.SetBackgroundColor(bgColor)
	chatArea.SetBorder(true)
	chatArea.SetTitle(" chat ")
	chatArea.SetTitleColor(accentColor)
	chatArea.SetBorderColor(borderColor)

	// Create the code display pane
	codeView := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter).
		SetText("\n[#6b6494]share this code[-]\n\n[#d946ef::b]" + code + "[-:-:-]")
	codeView.SetBackgroundColor(bgColor)
	codeView.SetBorder(true)
	codeView.SetTitle(" code ")
	codeView.SetTitleColor(accentColor)
	codeView.SetBorderColor(borderColor)

	// Create the input field
	input := tview.NewInputField().
		SetLabel("> ").
		SetLabelColor(accentColor).
		SetFieldWidth(0)
	input.SetBackgroundColor(bgColor)
	input.SetFieldBackgroundColor(bgColor)
	input.SetBorder(true)
	input.SetBorderColor(borderColor)

	// Prepare writer to send messages to peer
	writer := bufio.NewWriter(conn)
	autoScroll := true

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
				chatArea.Write([]byte("[#22d3ee::b]you[-:-:-] " + text + "\n"))
				// Prioritize new messages: re-enable autoscroll
				autoScroll = true
				chatArea.ScrollToEnd()
				input.SetText("")
			}
		}
	})

	// Start network reader: receive messages from connection and display.
	chatArea.SetChangedFunc(func() {
		if autoScroll {
			app.QueueUpdateDraw(func() {
				chatArea.ScrollToEnd()
			})
		} else {
			app.Draw()
		}
	})
	scrollDelta := func(delta int) {
		row, col := chatArea.GetScrollOffset()
		row += delta
		if row < 0 {
			row = 0
		}
		chatArea.ScrollTo(row, col)
	}

	app.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyPgUp, tcell.KeyUp:
			scrollDelta(-3)
			autoScroll = false
			return nil
		case tcell.KeyPgDn, tcell.KeyDown:
			scrollDelta(3)
			autoScroll = false
			return nil
		case tcell.KeyEnd:
			autoScroll = true
			chatArea.ScrollToEnd()
			return nil
		}
		return ev
	})

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
			chatArea.Write([]byte("[#d946ef::b]peer[-:-:-] " + line))
			autoScroll = true // prioridad a mensajes entrantes
			app.QueueUpdateDraw(func() {
				chatArea.ScrollToEnd()
			})
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
	flex.SetBorderColor(borderColor)
	flex.SetBorder(true)

	// Run the application (blocks until exit).
	// Disable mouse capture so terminal selection can work for copy/paste.
	if err := app.SetRoot(flex, true).Run(); err != nil {
		panic(err)
	}
}
