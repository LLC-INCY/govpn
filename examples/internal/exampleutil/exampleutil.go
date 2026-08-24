package exampleutil

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
)

func Context() context.Context {
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)
	return ctx
}

func Echo(ctx context.Context, listener net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}()
	}
}

func Interactive(conn net.Conn) error {
	defer conn.Close()
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(conn, os.Stdin)
		if closeWriter, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		} else {
			_ = conn.Close()
		}
		done <- err
	}()
	if _, err := io.Copy(os.Stdout, conn); err != nil {
		return err
	}
	return <-done
}

func Must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
