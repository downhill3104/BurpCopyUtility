package burp;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JComponent;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.TransferHandler;

public class BurpExtender implements IBurpExtender, IContextMenuFactory {

	private IExtensionHelpers helpers;

	@Override
	/**
	 * IBurpExtenderのメソッド
	 */
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks){
		helpers = callbacks.getHelpers();
		callbacks.setExtensionName("CopyUtility");
		callbacks.registerContextMenuFactory(this);
	}

	@Override
	public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
		List<JMenuItem> miList = new ArrayList<JMenuItem>();
		JMenuItem miCopy;
		JMenu miCopyCS;
		JMenuItem miCopyUTF8;
		JMenuItem miCopyEUCJP;
		JMenuItem miCopySJIS;
		JMenuItem miCopyJIS;
		switch ( invocation.getInvocationContext() ) {
		case IContextMenuInvocation.CONTEXT_PROXY_HISTORY:
			miCopy = new JMenuItem("Copy D&D");
			miCopy.setTransferHandler(new TransferHandler() {
	            @Override public int getSourceActions(JComponent c) {
	                return MOVE;
	            }
	            @Override protected Transferable createTransferable(JComponent c) {
                    return new TempFileTransferable(invocation);
	            }
	        });
			miCopy.addMouseListener(new MouseAdapter() {
	            @Override public void mousePressed(MouseEvent e) {
//	                System.out.println(e);
	                JComponent c = (JComponent) e.getComponent();
	                c.getTransferHandler().exportAsDrag(c, e, TransferHandler.MOVE);
	            }
	        });
			miList.add(miCopy);
			return miList;
		case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
		case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
			miCopy = new JMenuItem("Copy with Charset");
			miCopy.addActionListener(new ActionListener(){
				@Override public void actionPerformed(ActionEvent e) {
					byte[] request = invocation.getSelectedMessages()[0].getRequest();
					int[] range = invocation.getSelectionBounds();
					byte[] selection = Arrays.copyOfRange(request, range[0], range[1]);
					SetClipboard(new String(selection));
				}
			});
			miList.add(miCopy);
			miCopyCS = new JMenu("Copy of Charset");
			miCopyUTF8 = new JMenuItem("UTF-8");
			miCopyUTF8.addActionListener(new ActionListener(){
				@Override public void actionPerformed(ActionEvent e) {
					byte[] request = invocation.getSelectedMessages()[0].getRequest();
					int[] range = invocation.getSelectionBounds();
					byte[] selection = Arrays.copyOfRange(request, range[0], range[1]);
					SetClipboard(new String(selection, Charset.forName("UTF-8")));
				}
			});
			miCopyEUCJP = new JMenuItem("EUC-JP");
			miCopyEUCJP.addActionListener(new ActionListener(){
				@Override public void actionPerformed(ActionEvent e) {
					byte[] request = invocation.getSelectedMessages()[0].getRequest();
					int[] range = invocation.getSelectionBounds();
					byte[] selection = Arrays.copyOfRange(request, range[0], range[1]);
					SetClipboard(new String(selection, Charset.forName("EUC-JP")));
				}
			});
			miCopySJIS = new JMenuItem("Shift_JIS");
			miCopySJIS.addActionListener(new ActionListener(){
				@Override public void actionPerformed(ActionEvent e) {
					byte[] request = invocation.getSelectedMessages()[0].getRequest();
					int[] range = invocation.getSelectionBounds();
					byte[] selection = Arrays.copyOfRange(request, range[0], range[1]);
					SetClipboard(new String(selection, Charset.forName("Shift_JIS")));
				}
			});
			miCopyJIS = new JMenuItem("ISO-2022-JP");
			miCopyJIS.addActionListener(new ActionListener(){
				@Override public void actionPerformed(ActionEvent e) {
					byte[] request = invocation.getSelectedMessages()[0].getRequest();
					int[] range = invocation.getSelectionBounds();
					byte[] selection = Arrays.copyOfRange(request, range[0], range[1]);
					SetClipboard(new String(selection, Charset.forName("ISO-2022-JP")));
				}
			});
			miCopyCS.add(miCopyUTF8);
			miCopyCS.add(miCopyEUCJP);
			miCopyCS.add(miCopySJIS);
			miCopyCS.add(miCopyJIS);
			miList.add(miCopyCS);
			return miList;
		case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
		case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
			miCopy = new JMenuItem("Copy with Charset");
			miCopy.addActionListener(new ActionListener(){
				@Override public void actionPerformed(ActionEvent e) {
					byte[] response = invocation.getSelectedMessages()[0].getResponse();
					int[] range = invocation.getSelectionBounds();
					byte[] selection = Arrays.copyOfRange(response, range[0], range[1]);
					Charset cs = getCharset(response);
					if ( cs == null ) {
						cs = Charset.forName("UTF-8");
					}
					SetClipboard(new String(selection, cs));
				}
			});
			miList.add(miCopy);
			miCopyCS = new JMenu("Copy of Charset");
			miCopyUTF8 = new JMenuItem("UTF-8");
			miCopyUTF8.addActionListener(new ActionListener(){
				@Override public void actionPerformed(ActionEvent e) {
					byte[] response = invocation.getSelectedMessages()[0].getResponse();
					int[] range = invocation.getSelectionBounds();
					byte[] selection = Arrays.copyOfRange(response, range[0], range[1]);
					SetClipboard(new String(selection, Charset.forName("UTF-8")));
				}
			});
			miCopyEUCJP = new JMenuItem("EUC-JP");
			miCopyEUCJP.addActionListener(new ActionListener(){
				@Override public void actionPerformed(ActionEvent e) {
					byte[] response = invocation.getSelectedMessages()[0].getResponse();
					int[] range = invocation.getSelectionBounds();
					byte[] selection = Arrays.copyOfRange(response, range[0], range[1]);
					SetClipboard(new String(selection, Charset.forName("EUC-JP")));
				}
			});
			miCopySJIS = new JMenuItem("Shift_JIS");
			miCopySJIS.addActionListener(new ActionListener(){
				@Override public void actionPerformed(ActionEvent e) {
					byte[] response = invocation.getSelectedMessages()[0].getResponse();
					int[] range = invocation.getSelectionBounds();
					byte[] selection = Arrays.copyOfRange(response, range[0], range[1]);
					SetClipboard(new String(selection, Charset.forName("Shift_JIS")));
				}
			});
			miCopyJIS = new JMenuItem("ISO-2022-JP");
			miCopyJIS.addActionListener(new ActionListener(){
				@Override public void actionPerformed(ActionEvent e) {
					byte[] response = invocation.getSelectedMessages()[0].getResponse();
					int[] range = invocation.getSelectionBounds();
					byte[] selection = Arrays.copyOfRange(response, range[0], range[1]);
					SetClipboard(new String(selection, Charset.forName("ISO-2022-JP")));
				}
			});
			miCopyCS.add(miCopyUTF8);
			miCopyCS.add(miCopyEUCJP);
			miCopyCS.add(miCopySJIS);
			miCopyCS.add(miCopyJIS);
			miList.add(miCopyCS);
			return miList;
		}
		return null;
	}

	private void SetClipboard(String str) {
		Toolkit kit = Toolkit.getDefaultToolkit();
		Clipboard clip = kit.getSystemClipboard();
		StringSelection ss = new StringSelection(str);
		clip.setContents(ss, ss);
	}

	private Charset getCharset(byte[] response) {
//		IResponseInfo resInfo = helpers.analyzeResponse(response);

/*
		List<String> headers = resInfo.getHeaders();
		Pattern regex = Pattern.compile("charset=([A-Za-z0-9\\-\\+\\.:_]+)", Pattern.CASE_INSENSITIVE);
		for ( String header : headers ) {
			if ( header.indexOf("Content-Type: ") == 0 && header.indexOf("charset=") > 0 ) {
				Matcher m = regex.matcher(header);
				if ( m.find() ) {
					JOptionPane.showMessageDialog(null, m.group(1));
					return Charset.forName(m.group(1));
				}
			}
		}
*/

		Pattern regex = Pattern.compile("(?:charset|encoding)=[^A-Za-z0-9\\-\\+\\.:_]?([A-Za-z0-9\\-\\+\\.:_]+)", Pattern.CASE_INSENSITIVE);
		Matcher m = regex.matcher(helpers.bytesToString(response));
		if ( m.find() ) {
			return Charset.forName(m.group(1));
		}
//		byte[] resBody = Arrays.copyOfRange(response, resInfo.getBodyOffset(), response.length - 1);
/*
		String[] resLines = helpers.bytesToString(response).split("(\r\n|\n|\r)");
		for ( int i = 0; i < resLines.length; ++i ) {
			Matcher m = regex.matcher(resLines[i]);
			if ( m.find() ) {
				JOptionPane.showMessageDialog(null, m.group(1));
				return Charset.forName(m.group(1));
			}
		}
*/

		return null;
	}

	class TempFileTransferable implements Transferable {
	    private File file = null;
	    public TempFileTransferable(IContextMenuInvocation invocation) {
            try {
                file = File.createTempFile("burp_request_response_", ".txt");
                file.deleteOnExit();
                FileOutputStream fos = new FileOutputStream(file);
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
    			for ( int i = 0; i < messages.length; ++i ) {
    				fos.write(messages[i].getRequest());
    				fos.write(new String("\r\n======================================================\r\n").getBytes());
    				fos.write(messages[i].getResponse());
    				fos.write(new String("\r\n======================================================\r\n").getBytes());
    			}
	            fos.close();
            } catch (FileNotFoundException e) {
            } catch (IOException ioe) {
            }
	    }
	    @Override public Object getTransferData(DataFlavor flavor) {
	        return Arrays.asList(file);
	    }
	    @Override public DataFlavor[] getTransferDataFlavors() {
	        return new DataFlavor[] {DataFlavor.javaFileListFlavor};
	    }
	    @Override public boolean isDataFlavorSupported(DataFlavor flavor) {
	        return flavor.equals(DataFlavor.javaFileListFlavor);
	    }
	}
}
