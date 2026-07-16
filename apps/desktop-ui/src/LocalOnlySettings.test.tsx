import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { LocalOnlySettings } from "./LocalOnlySettings";

describe("local-only settings", () => {
  it("enables local-only explicitly without optimistic mode", async () => {
    let resolve!: () => void;
    const onSetLocalOnly = vi.fn(
      () =>
        new Promise<void>((done) => {
          resolve = done;
        }),
    );
    const user = userEvent.setup();
    const view = render(
      <LocalOnlySettings
        localOnly={false}
        revision={8}
        authorityHealth="persisted"
        onSetLocalOnly={onSetLocalOnly}
      />,
    );
    const modeSwitch = screen.getByRole("switch", {
      name: "Personal live",
    });

    await user.click(modeSwitch);

    expect(onSetLocalOnly).toHaveBeenCalledWith(true, 8);
    expect(modeSwitch).toHaveAttribute("aria-checked", "false");
    expect(modeSwitch).toBeDisabled();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    resolve();
    await waitFor(() => expect(modeSwitch).toBeEnabled());
    expect(modeSwitch).toHaveAttribute("aria-checked", "false");

    view.rerender(
      <LocalOnlySettings
        localOnly
        revision={9}
        authorityHealth="persisted"
        onSetLocalOnly={onSetLocalOnly}
      />,
    );
    expect(
      screen.getByRole("switch", { name: "Local only" }),
    ).toHaveAttribute("aria-checked", "true");
    expect(screen.getByRole("status")).toHaveTextContent(
      "Local-only mode enabled.",
    );
  });

  it("names outbound providers, cancels without changing mode, and restores focus", async () => {
    const onSetLocalOnly = vi.fn(async () => undefined);
    const user = userEvent.setup();
    render(
      <LocalOnlySettings
        localOnly
        revision={11}
        authorityHealth="fail_closed_uncertain"
        onSetLocalOnly={onSetLocalOnly}
      />,
    );
    const modeSwitch = screen.getByRole("switch", { name: "Local only" });

    await user.click(modeSwitch);

    const dialog = screen.getByRole("dialog", {
      name: "Enable personal live?",
    });
    expect(dialog).toHaveTextContent("Gmail");
    expect(dialog).toHaveTextContent("OpenAI");
    expect(dialog).toHaveTextContent("receipt-image downloads");
    expect(dialog).toHaveTextContent("cloud-backed Apple Photos");
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus();

    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(onSetLocalOnly).not.toHaveBeenCalled();
    await waitFor(() => expect(modeSwitch).toHaveFocus());

    await user.click(modeSwitch);
    await user.click(
      within(screen.getByRole("dialog")).getByRole("button", {
        name: "Enable personal live",
      }),
    );

    await waitFor(() =>
      expect(onSetLocalOnly).toHaveBeenCalledWith(false, 11),
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(modeSwitch).toHaveAttribute("aria-checked", "true");
    await waitFor(() => expect(modeSwitch).toHaveFocus());
  });
});
